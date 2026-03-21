# IAM Role Abuse

## The Problem

IAM roles grant temporary credentials to AWS services, users, or external identities. When role trust policies are too permissive or roles are over-privileged, attackers can assume them to escalate access.

---

## Attack Scenarios

### Scenario 1 — EC2 Instance Role Credential Theft
```bash
# Attacker with shell access on an EC2 instance runs:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name, e.g.: MyAppRole

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole
# Returns:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }

# Attacker exports these and uses them from their own machine
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls  # Works from anywhere until TTL expires
```

### Scenario 2 — Overly Permissive Trust Policy
```json
// Dangerous: Any AWS account can assume this role
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::*:root"
  },
  "Action": "sts:AssumeRole"
}
```

### Scenario 3 — Role Chaining for Privilege Escalation
```bash
# Attacker assumes Role A (low privilege)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789:role/LowPrivRole \
  --role-session-name attacker-session

# Role A has sts:AssumeRole on Role B (high privilege)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789:role/AdminRole \
  --role-session-name escalated-session
# Now attacker has admin access
```

---

## Detection

```bash
# 1. Find roles with wildcard Principal in trust policy
aws iam list-roles --query 'Roles[*].RoleName' --output text | \
  tr '\t' '\n' | while read role; do
    trust=$(aws iam get-role --role-name "$role" \
      --query 'Role.AssumeRolePolicyDocument' --output json)
    if echo "$trust" | grep -q '"AWS": "\*"'; then
      echo "DANGEROUS TRUST POLICY: $role"
    fi
  done

# 2. Find roles that can be assumed by all AWS services
aws iam list-roles \
  --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal==`"*"`]].RoleName'

# 3. Monitor AssumeRole calls in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,SourceIPAddress]' \
  --output table

# 4. Find roles with AdministratorAccess attached
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --entity-filter Role \
  --query 'PolicyRoles[*].RoleName'
```

---

## Prevention

### 1. Enforce IMDSv2 to Block Credential Theft from EC2
```bash
# Enforce on a running instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled

# Verify
aws ec2 describe-instances \
  --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[*].Instances[*].MetadataOptions'

# Enforce org-wide via AWS Config rule
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "ec2-imdsv2-check",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "EC2_IMDSV2_REQUIRED"
  }
}'
```

### 2. Tighten Trust Policies — Always Specify Exact Principal
```bash
# Check trust policy for a role
aws iam get-role \
  --role-name MyRole \
  --query 'Role.AssumeRolePolicyDocument'

# Update trust policy to restrict principal
aws iam update-assume-role-policy \
  --role-name MyRole \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SpecificRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-12345"
        }
      }
    }]
  }'
```

### 3. Use Permission Boundaries to Cap Role Privileges
```bash
# Create a permission boundary
aws iam create-policy \
  --policy-name MaxPermissionBoundary \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-app-bucket/*"
    }]
  }'

# Attach boundary to role — role can NEVER exceed this even if policy says otherwise
aws iam put-role-permissions-boundary \
  --role-name MyAppRole \
  --permissions-boundary arn:aws:iam::123456789:policy/MaxPermissionBoundary
```

### 4. SCP — Prevent Roles from Being Created Without Boundaries
```json
// Attach this SCP to your AWS Organization
{
  "Effect": "Deny",
  "Action": ["iam:CreateRole", "iam:PutRolePolicy"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "iam:PermissionsBoundary": "arn:aws:iam::*:policy/MaxPermissionBoundary"
    }
  }
}
```

---

## Checklist

- [ ] No roles with `Principal: "*"` in trust policy
- [ ] Cross-account role assumptions use `sts:ExternalId`
- [ ] Permission boundaries applied to all non-service roles
- [ ] IMDSv2 enforced on all EC2 instances
- [ ] CloudTrail alerting on unexpected `AssumeRole` calls
- [ ] IAM Access Analyzer enabled in all regions
