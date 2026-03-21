# GuardDuty — Threat Detection, Findings, and Automated Response

## Attack Scenarios

### Scenario 1 — Finding Ignored, Breach Ongoing for Weeks
```bash
# GuardDuty raises: UnauthorizedAccess:IAMUser/TorIPCaller
# Finding sits in console — no SNS, no PagerDuty, no Slack hook
# Nobody checks the GuardDuty console because "it's always firing"

# Meanwhile attacker is:
# - Enumerating IAM roles (Recon:IAMUser/UserPermissions)
# - Creating backdoor users (Persistence:IAMUser/UserCreations)
# - Mining crypto (CryptoCurrency:EC2/BitcoinTool.B)
# All with corresponding GuardDuty findings — all unread
```

### Scenario 2 — GuardDuty Disabled by Attacker
```bash
# After gaining admin access:
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty delete-detector --detector-id $DETECTOR_ID
# All future threat detection is now blind
# Without an SCP: single command, instant impact
```

### Scenario 3 — Credential Exfiltration Not Acted On
```bash
# GuardDuty raises: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
# This means: EC2 role credentials are being used from outside AWS (attacker's laptop)
# Alert fires at 2am, nobody responds until morning
# By then: all S3 data has been exfiltrated, backdoor user created, CloudTrail stopped
```

---

## Key GuardDuty Finding Types

```
Finding                                              What It Means
──────────────────────────────────────────────────────────────────────────────
UnauthorizedAccess:IAMUser/ConsoleLoginSuccess       Login from unusual location/IP
UnauthorizedAccess:IAMUser/TorIPCaller               API calls from Tor exit node
Recon:IAMUser/UserPermissions                        Attacker enumerating IAM
Recon:IAMUser/NetworkPermissions                     Attacker enumerating VPC/SGs
Persistence:IAMUser/UserCreations                    New IAM user created (backdoor)
Persistence:IAMUser/UserPermissions                  IAM policy changes for persistence
Impact:IAMUser/AnomalousBehavior                     Unusual volume of API calls
InstanceCredentialExfiltration.OutsideAWS            EC2 creds used outside AWS
CryptoCurrency:EC2/BitcoinTool.B                     Crypto miner running on EC2
Backdoor:EC2/C&CActivity.B                           EC2 calling known C2 server
UnauthorizedAccess:EC2/SSHBruteForce                 SSH brute force in progress
Discovery:S3/BucketEnumeration.Unusual               Attacker listing your buckets
Exfiltration:S3/ObjectRead.Unusual                   Unusual volume of S3 reads
Policy:S3/BucketBlockPublicAccessDisabled            Block public access turned off
```

---

## Setup — Enable GuardDuty Properly

```bash
# 1. Enable GuardDuty in current region
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --features '[
    {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
    {"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"},
    {"Name": "MALWARE_PROTECTION", "Status": "ENABLED"},
    {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
    {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"}
  ]'

DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
echo "Detector ID: $DETECTOR_ID"

# 2. Enable in ALL regions (use this loop)
for region in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text | tr '\t' '\n'); do
  echo "Enabling GuardDuty in $region..."
  aws guardduty create-detector \
    --enable \
    --finding-publishing-frequency FIFTEEN_MINUTES \
    --region "$region" 2>/dev/null || echo "Already enabled or error in $region"
done

# 3. SCP — prevent disabling GuardDuty
aws organizations create-policy \
  --name ProtectGuardDuty \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector"
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

## Alerting — Never Rely on the Console

```bash
# Connect GuardDuty findings to SNS via EventBridge
# This fires on ANY GuardDuty finding

aws events put-rule \
  --name GuardDutyFindings \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"]
  }' \
  --state ENABLED

# Create SNS topic for alerts
aws sns create-topic --name SecurityAlerts
aws sns subscribe \
  --topic-arn arn:aws:sns:ap-south-1:123456789:SecurityAlerts \
  --protocol email \
  --notification-endpoint sharan@company.com

# Route HIGH and CRITICAL findings to SNS
aws events put-rule \
  --name GuardDutyHighSeverity \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{"numeric": [">=", 7]}]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule GuardDutyHighSeverity \
  --targets 'Id=SNSTarget,Arn=arn:aws:sns:ap-south-1:123456789:SecurityAlerts'
```

---

## Automated Response — EventBridge + Lambda

```bash
# Auto-response: If GuardDuty detects credential exfiltration,
# automatically deactivate the access key

# Create the response Lambda
cat > /tmp/response.py <<'EOF'
import boto3
import json

def handler(event, context):
    detail = event['detail']
    finding_type = detail['type']
    severity = detail['severity']

    print(f"GuardDuty finding: {finding_type} (severity: {severity})")

    # Handle credential exfiltration
    if 'InstanceCredentialExfiltration' in finding_type:
        # Get the affected role
        principal = detail.get('resource', {}).get('accessKeyDetails', {})
        access_key_id = principal.get('accessKeyId', '')
        user_name = principal.get('userName', '')

        if access_key_id:
            print(f"Deactivating compromised key: {access_key_id} for user {user_name}")
            iam = boto3.client('iam')
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            print(f"Key {access_key_id} deactivated automatically")

    # Handle crypto mining
    if 'CryptoCurrency' in finding_type:
        ec2_details = detail.get('resource', {}).get('instanceDetails', {})
        instance_id = ec2_details.get('instanceId', '')
        if instance_id:
            print(f"Isolating crypto-mining instance: {instance_id}")
            ec2 = boto3.client('ec2')
            # Isolate by applying a deny-all security group
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=['sg-isolation-sg']  # Pre-created SG with no rules
            )

    return {'statusCode': 200}
EOF

# Route the finding to this Lambda
aws events put-targets \
  --rule GuardDutyHighSeverity \
  --targets "Id=AutoResponse,Arn=arn:aws:lambda:ap-south-1:123456789:function:GuardDutyAutoResponse"
```

---

## Forensics — Query Findings

```bash
# List all active HIGH/CRITICAL findings
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

aws guardduty list-findings \
  --detector-id $DETECTOR_ID \
  --finding-criteria '{
    "Criterion": {
      "severity": {"Gte": 7},
      "service.archived": {"Eq": ["false"]}
    }
  }' \
  --query 'FindingIds' --output text | tr '\t' '\n' | head -20 | \
  xargs -I{} aws guardduty get-findings \
    --detector-id $DETECTOR_ID \
    --finding-ids {} \
    --query 'Findings[*].[Type,Severity,Title,UpdatedAt,Region]' \
    --output table

# Get details on a specific finding
aws guardduty get-findings \
  --detector-id $DETECTOR_ID \
  --finding-ids <finding-id> \
  --output json | python3 -m json.tool
```

---

## Checklist

- [ ] GuardDuty enabled in ALL regions — not just primary region
- [ ] All GuardDuty protection plans enabled (S3, EKS, Malware, RDS, Lambda)
- [ ] SCP blocks `guardduty:DeleteDetector` and `DisassociateFromMasterAccount`
- [ ] EventBridge rule routing HIGH/CRITICAL findings to SNS
- [ ] On-call team subscribed to SNS alerts — not just email
- [ ] Automated response Lambda for credential exfiltration findings
- [ ] GuardDuty findings exported to Security Hub for aggregation
- [ ] Findings reviewed weekly — archive resolved ones to reduce noise
- [ ] Trusted IP list configured to reduce false positives from your office IPs
