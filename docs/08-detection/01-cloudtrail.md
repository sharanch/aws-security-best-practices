# CloudTrail — Hardening, Log Protection, and Forensic Queries

## Attack Scenarios

### Scenario 1 — Attacker Disables CloudTrail Immediately
```bash
# First thing a sophisticated attacker does after gaining admin access:
aws cloudtrail stop-logging --name my-trail
# All subsequent API calls are now unlogged
# Without an SCP blocking this — it takes one command

# Or deletes the trail entirely
aws cloudtrail delete-trail --name my-trail

# Or deletes the S3 bucket storing logs
aws s3 rb s3://my-cloudtrail-logs --force
```

### Scenario 2 — Single-Region Trail Misses Activity
```bash
# Trail only covers ap-south-1
# Attacker pivots to us-east-1 (common default for IAM, STS, S3 global calls)
aws ec2 run-instances \
  --region us-east-1 \
  --image-id ami-12345678 \
  --instance-type t3.large
# Crypto miner running in us-east-1 — zero trail entries in your ap-south-1 trail
```

### Scenario 3 — Log Tampering — Gaps in Logs
```bash
# If log file validation is disabled, attacker can:
# 1. Delete specific log files from S3
# 2. Modify log files to remove evidence
# 3. You have no way to detect the tampering

# With log file validation enabled, each log file is hashed and chained
# Any deletion or modification breaks the chain — detectable
```

---

## Detection — Verify CloudTrail Health

```bash
# 1. Check all trails and their status
aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,LogFileValidationEnabled,S3BucketName]' \
  --output table

# 2. Check if logging is actually active (trail can exist but be stopped)
aws cloudtrail get-trail-status \
  --name my-trail \
  --query '[IsLogging,LatestDeliveryTime,LatestDeliveryError]' \
  --output table

# 3. Validate log file integrity
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:ap-south-1:123456789:trail/my-trail \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --verbose
# Any "Invalid" entries = tampering detected

# 4. Check if S3 data events are enabled (S3 object-level logging)
aws cloudtrail get-event-selectors --trail-name my-trail \
  --query 'EventSelectors[*].[ReadWriteType,IncludeManagementEvents,DataResources]'
```

---

## Fix — Harden CloudTrail

```bash
# Fix 1: Create a multi-region trail with all protections
aws cloudtrail create-trail \
  --name org-security-trail \
  --s3-bucket-name my-cloudtrail-logs \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:ap-south-1:123456789:key/key-id \
  --tags-list Key=Purpose,Value=SecurityAudit

aws cloudtrail start-logging --name org-security-trail

# Fix 2: Enable S3 data events (captures GetObject, PutObject, DeleteObject)
aws cloudtrail put-event-selectors \
  --trail-name org-security-trail \
  --event-selectors '[
    {
      "ReadWriteType": "All",
      "IncludeManagementEvents": true,
      "DataResources": [
        {
          "Type": "AWS::S3::Object",
          "Values": ["arn:aws:s3:::sensitive-bucket/"]
        },
        {
          "Type": "AWS::Lambda::Function",
          "Values": ["arn:aws:lambda"]
        }
      ]
    }
  ]'

# Fix 3: Lock the CloudTrail S3 bucket — prevent deletion
aws s3api put-bucket-policy \
  --bucket my-cloudtrail-logs \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["s3:DeleteObject", "s3:DeleteBucket", "s3:PutBucketPolicy"],
        "Resource": [
          "arn:aws:s3:::my-cloudtrail-logs",
          "arn:aws:s3:::my-cloudtrail-logs/*"
        ],
        "Condition": {
          "StringNotEquals": {
            "aws:PrincipalArn": "arn:aws:iam::123456789:role/SecurityAdminRole"
          }
        }
      }
    ]
  }'

# Fix 4: SCP — prevent stopping or deleting CloudTrail
aws organizations create-policy \
  --name ProtectCloudTrail \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::123456789:role/SecurityAdminRole"
        }
      }
    }]
  }'
```

---

## Forensic Queries — CloudTrail Lookup

```bash
# 1. What did a specific user do in the last 24 hours?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=sharan \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress,AwsRegion]' \
  --output table

# 2. What happened with a specific access key?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress]' \
  --output table

# 3. All root account activity (should be near zero)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,EventName,SourceIPAddress]' \
  --output table

# 4. All IAM changes in last 24 hours
for event in CreateUser DeleteUser AttachRolePolicy DetachRolePolicy \
             CreateAccessKey DeleteAccessKey AddUserToGroup; do
  echo "=== $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$event \
    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[*].[EventTime,Username,SourceIPAddress]' \
    --output table
done

# 5. CloudWatch Insights — high-level anomaly query
aws logs start-query \
  --log-group-name aws-cloudtrail-logs \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields eventTime, userIdentity.userName, eventName, sourceIPAddress, errorCode
    | filter errorCode like /AccessDenied/
    | stats count(*) as denied_count by userIdentity.userName, sourceIPAddress
    | sort denied_count desc
    | limit 20'
# High AccessDenied count = reconnaissance or attack in progress
```

---

## Critical CloudWatch Alarms

```bash
# Alarm 1: Root account login
aws logs put-metric-filter \
  --log-group-name aws-cloudtrail-logs \
  --filter-name RootLogin \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.eventName = "ConsoleLogin" }' \
  --metric-transformations metricName=RootLoginCount,metricNamespace=CloudTrailAlarms,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountLogin \
  --metric-name RootLoginCount \
  --namespace CloudTrailAlarms \
  --statistic Sum --period 300 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:ap-south-1:123456789:SecurityAlerts

# Alarm 2: CloudTrail stopped
aws logs put-metric-filter \
  --log-group-name aws-cloudtrail-logs \
  --filter-name CloudTrailStopped \
  --filter-pattern '{ $.eventName = "StopLogging" }' \
  --metric-transformations metricName=CloudTrailStoppedCount,metricNamespace=CloudTrailAlarms,metricValue=1

# Alarm 3: IAM policy change
aws logs put-metric-filter \
  --log-group-name aws-cloudtrail-logs \
  --filter-name IAMPolicyChange \
  --filter-pattern '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "DeleteGroupPolicy" || $.eventName = "DeleteRolePolicy" || $.eventName = "AttachRolePolicy" || $.eventName = "DetachRolePolicy") }' \
  --metric-transformations metricName=IAMPolicyChangeCount,metricNamespace=CloudTrailAlarms,metricValue=1
```

---

## Checklist

- [ ] Multi-region trail enabled covering all regions including global services
- [ ] Log file validation enabled — detects tampering
- [ ] CloudTrail logs encrypted with customer-managed KMS key
- [ ] CloudTrail S3 bucket has delete-protection policy
- [ ] SCP blocks `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail`
- [ ] S3 data events enabled on sensitive buckets
- [ ] CloudWatch metric filters + alarms on root login, IAM changes, trail stoppage
- [ ] Log retention set to 1 year minimum in S3
- [ ] CloudWatch log group for CloudTrail set to 90 day retention
