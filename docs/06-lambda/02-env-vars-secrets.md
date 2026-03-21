# Lambda — Secrets in Environment Variables

## Attack Scenarios

### Scenario 1 — Environment Variable Harvesting
```python
# Common anti-pattern — secrets stored as Lambda env vars
# Visible in AWS Console, CLI, and any code running in the function

import os

DB_PASSWORD = os.environ['DB_PASSWORD']       # Plaintext in Lambda config
API_KEY = os.environ['THIRD_PARTY_API_KEY']   # Visible to anyone with lambda:GetFunctionConfiguration
STRIPE_SECRET = os.environ['STRIPE_SECRET_KEY']

# Anyone who can run:
aws lambda get-function-configuration --function-name my-function
# ...can read ALL environment variables in plaintext
# Required permission: lambda:GetFunctionConfiguration — often granted broadly
```

### Scenario 2 — Env Vars Leaked in Error Logs
```python
# Unhandled exception dumps environment to CloudWatch Logs
import os
import traceback

def handler(event, context):
    try:
        process(event)
    except Exception as e:
        # Anti-pattern: printing full environment on error
        print(f"Error occurred. Environment: {dict(os.environ)}")
        # DB_PASSWORD=prod-secret-123, API_KEY=sk-live-xxxx now in CloudWatch Logs
        raise
```

### Scenario 3 — Env Vars in Deployment Artifacts
```yaml
# serverless.yml / SAM template committed to git
functions:
  myFunction:
    environment:
      DB_PASSWORD: prod-secret-123        # Hardcoded in IaC template
      STRIPE_SECRET: sk_live_xxxxxxxx     # In version control forever
      JWT_SECRET: my-super-secret-key
```

---

## Detection

```bash
# 1. Find Lambda functions with suspicious environment variable names
aws lambda list-functions \
  --query 'Functions[*].FunctionName' --output text | tr '\t' '\n' | \
  while read -r fn; do
    env_vars=$(aws lambda get-function-configuration \
      --function-name "$fn" \
      --query 'Environment.Variables' --output json 2>/dev/null || echo "{}")

    # Check for common secret patterns in key names
    echo "$env_vars" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
risky_patterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL', 'PRIVATE', 'API_KEY']
for k in d.keys():
    if any(p in k.upper() for p in risky_patterns):
        print(f'WARNING: Function has suspicious env var: {k}')
" 2>/dev/null
  done

# 2. Check if env vars are encrypted with KMS (not just default Lambda encryption)
aws lambda get-function-configuration \
  --function-name my-function \
  --query 'KMSKeyArn'
# Empty = using default Lambda encryption (weaker)
# Should be a customer-managed KMS key ARN

# 3. CloudTrail — who accessed function configuration recently
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetFunctionConfiguration \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,SourceIPAddress]' \
  --output table

# 4. Scan IaC templates for hardcoded secrets
pip install trufflehog --break-system-packages 2>/dev/null || true
# trufflehog filesystem --path ./infrastructure/
```

---

## Fix — Fetch Secrets from Secrets Manager at Runtime

```python
# Fix: fetch secrets at cold start, cache them — never store in env vars
import boto3
import json
import os

# Module-level cache — fetched once per container, not per invocation
_secrets_cache = {}

def get_secret(secret_name: str) -> dict:
    if secret_name not in _secrets_cache:
        client = boto3.client('secretsmanager',
                              region_name=os.environ['AWS_REGION'])
        response = client.get_secret_value(SecretId=secret_name)
        _secrets_cache[secret_name] = json.loads(response['SecretString'])
    return _secrets_cache[secret_name]

def handler(event, context):
    # Fetched once per Lambda container lifetime
    db_creds = get_secret('prod/myapp/db-credentials')
    db_password = db_creds['password']

    # Use db_password — never printed, never in env vars
    return process(event, db_password)
```

```bash
# Execution role needs only GetSecretValue on the specific secret
aws iam put-role-policy \
  --role-name my-lambda-role \
  --policy-name SecretsManagerAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:ap-south-1:123456789:secret:prod/myapp/*"
    }]
  }'

# Encrypt remaining non-sensitive env vars with customer KMS key
aws lambda update-function-configuration \
  --function-name my-function \
  --kms-key-arn arn:aws:kms:ap-south-1:123456789:key/your-key-id \
  --environment 'Variables={APP_ENV=production,LOG_LEVEL=info}'
# Only truly non-sensitive config goes in env vars
# Secrets always come from Secrets Manager

# Remove an existing sensitive env var
aws lambda update-function-configuration \
  --function-name my-function \
  --environment 'Variables={APP_ENV=production}'
# DB_PASSWORD is now gone from env vars — fetch from Secrets Manager instead
```

---

## Use Lambda Extensions for Secrets Caching (AWS Best Practice)

```bash
# AWS Parameters and Secrets Lambda Extension
# Caches secrets locally in the Lambda execution environment
# Reduces Secrets Manager API calls

# Add the extension layer (region-specific ARN)
aws lambda update-function-configuration \
  --function-name my-function \
  --layers arn:aws:lambda:ap-south-1:175048686990:layer:AWS-Parameters-and-Secrets-Lambda-Extension:11

# Then fetch via localhost HTTP — extension handles caching
# In your function code:
python3 - <<'EOF'
import urllib.request
import json

def get_secret(secret_name):
    url = f"http://localhost:2773/secretsmanager/get?secretId={secret_name}"
    req = urllib.request.Request(url, headers={"X-Aws-Parameters-Secrets-Token": open("/tmp/aws-token").read().strip() if False else ""})
    # Extension handles auth automatically via AWS_SESSION_TOKEN env
    with urllib.request.urlopen(url) as response:
        return json.loads(json.loads(response.read())['SecretString'])
EOF
```

---

## Checklist

- [ ] No secrets, passwords, tokens, or API keys in Lambda environment variables
- [ ] Secrets fetched from Secrets Manager or Parameter Store at runtime
- [ ] Lambda execution role has `secretsmanager:GetSecretValue` scoped to specific ARNs only
- [ ] Customer-managed KMS key used for env var encryption
- [ ] Error handlers do not log `os.environ` or full exception tracebacks
- [ ] IaC templates (SAM, Serverless, CDK) scanned for hardcoded secrets before commit
- [ ] `lambda:GetFunctionConfiguration` permission restricted — not broadly granted
