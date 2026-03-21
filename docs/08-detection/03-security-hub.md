# Security Hub — Aggregation, Standards, and SIEM Integration

## Attack Scenarios

### Scenario 1 — Siloed Findings Nobody Sees
```bash
# Without Security Hub:
# GuardDuty findings  → GuardDuty console
# Config rules        → AWS Config console
# Inspector findings  → Inspector console
# Macie findings      → Macie console
# IAM Access Analyzer → IAM console

# Security team checks 5 separate consoles
# Or more realistically: checks none of them
# A critical finding from Inspector about an unpatched CVE
# sits for 3 months because nobody looked
```

### Scenario 2 — No Compliance Baseline
```bash
# Without CIS Benchmark enabled in Security Hub:
# - No systematic check for root MFA
# - No check for CloudTrail in all regions
# - No check for security groups with 0.0.0.0/0
# Each of these would be a separate manual audit

# With CIS enabled: Security Hub scores your account 0-100
# and lists every failing control with remediation guidance
```

### Scenario 3 — Findings Not Exported to SIEM
```bash
# SOC team uses Splunk or Elasticsearch for incident response
# AWS findings stay inside AWS — SOC team has no visibility
# Attacker detected by GuardDuty at 2am
# SOC team doesn't see it until they log into AWS console next morning
```

---

## Setup — Enable Security Hub

```bash
# 1. Enable Security Hub
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-finding-generator SECURITY_CONTROL

# 2. Enable specific security standards
# CIS AWS Foundations Benchmark
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0

# AWS Foundational Security Best Practices
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:ap-south-1::standards/aws-foundational-security-best-practices/v/1.0.0

# NIST SP 800-53 (if compliance required)
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:ap-south-1::standards/nist-800-53/v/5.0.0

# 3. Enable GuardDuty integration (sends findings to Security Hub)
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:ap-south-1::product/aws/guardduty

# 4. Enable other integrations
aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:ap-south-1::product/aws/inspector

aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:ap-south-1::product/aws/macie

aws securityhub enable-import-findings-for-product \
  --product-arn arn:aws:securityhub:ap-south-1::product/aws/access-analyzer
```

---

## Querying Findings

```bash
# 1. Get overall security score per standard
aws securityhub describe-standards-controls \
  --standards-subscription-arn arn:aws:securityhub:ap-south-1:123456789:subscription/cis-aws-foundations-benchmark/v/1.4.0 \
  --query 'Controls[?ControlStatus==`FAILED`].[ControlId,Title,SeverityRating]' \
  --output table

# 2. List all CRITICAL findings
aws securityhub get-findings \
  --filters '{
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[*].[Title,ProductName,UpdatedAt,Description]' \
  --output table

# 3. Find findings about specific resources
aws securityhub get-findings \
  --filters '{
    "ResourceId": [{"Value": "arn:aws:s3:::my-bucket", "Comparison": "CONTAINS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[*].[Title,Severity.Label,ProductName]' \
  --output table

# 4. Count findings by severity
aws securityhub get-findings \
  --filters '{"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}' \
  --query 'Findings[*].Severity.Label' \
  --output text | tr '\t' '\n' | sort | uniq -c | sort -rn

# 5. Get specific CIS controls that are failing
aws securityhub get-findings \
  --filters '{
    "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "SeverityLabel": [{"Value": "HIGH", "Comparison": "EQUALS"}]
  }' \
  --query 'Findings[*].[Title,Remediation.Recommendation.Text]' \
  --output table
```

---

## Automated Alerting and Suppression

```bash
# Route CRITICAL findings to PagerDuty/SNS via EventBridge
aws events put-rule \
  --name SecurityHubCritical \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Severity": {
          "Label": ["CRITICAL", "HIGH"]
        },
        "Workflow": {
          "Status": ["NEW"]
        },
        "RecordState": ["ACTIVE"]
      }
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule SecurityHubCritical \
  --targets 'Id=SecurityAlertsSNS,Arn=arn:aws:sns:ap-south-1:123456789:SecurityAlerts'

# Suppress known false positives (e.g., specific test accounts)
aws securityhub batch-update-findings \
  --finding-identifiers '[{"Id": "finding-id", "ProductArn": "product-arn"}]' \
  --workflow '{"Status": "SUPPRESSED"}' \
  --note '{"Text": "Test account — expected behavior", "UpdatedBy": "sharan"}'
```

---

## Export to SIEM (Splunk / Elasticsearch)

```bash
# Option 1: Kinesis Firehose to S3, then SIEM picks up from S3
aws firehose create-delivery-stream \
  --delivery-stream-name SecurityHubToS3 \
  --s3-destination-configuration '{
    "RoleARN": "arn:aws:iam::123456789:role/FirehoseRole",
    "BucketARN": "arn:aws:s3:::siem-ingestion-bucket",
    "Prefix": "securityhub/",
    "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": 300},
    "CompressionFormat": "GZIP"
  }'

# Route Security Hub findings to Firehose via EventBridge
aws events put-targets \
  --rule SecurityHubCritical \
  --targets 'Id=FirehoseTarget,Arn=arn:aws:firehose:ap-south-1:123456789:deliverystream/SecurityHubToS3'

# Option 2: Use AWS Security Lake (centralizes all security data)
# Normalizes to OCSF format — works with any SIEM
aws securitylake create-data-lake \
  --configurations '[
    {
      "region": "ap-south-1",
      "encryptionConfiguration": {
        "kmsKeyId": "arn:aws:kms:ap-south-1:123456789:key/key-id"
      }
    }
  ]'
```

---

## Checklist

- [ ] Security Hub enabled in all regions
- [ ] CIS AWS Foundations Benchmark standard enabled
- [ ] AWS Foundational Security Best Practices standard enabled
- [ ] GuardDuty, Inspector, Macie, and Access Analyzer integrations enabled
- [ ] Cross-region aggregation configured — one region as primary
- [ ] EventBridge routing CRITICAL/HIGH findings to SNS and on-call
- [ ] Security score reviewed weekly — target 90%+
- [ ] SIEM integration via Kinesis Firehose or Security Lake
- [ ] Suppression rules for known false positives (documented)
- [ ] Finding SLAs defined — CRITICAL resolved within 24h, HIGH within 7 days
