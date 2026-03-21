# Secrets Management in CI/CD Pipelines

## The Problem

Secrets hardcoded in repos, printed in build logs, or stored as plaintext CI variables are one of the most common causes of breaches. Bots scan public repos continuously.

---

## Attack Scenarios

```bash
# Scenario 1 — Secret accidentally printed in CI log
- name: Deploy
  run: |
    echo "Deploying with DB password: $DB_PASSWORD"  # Oops — visible in logs
    ./deploy.sh

# Scenario 2 — Debug step leaks all env vars
- name: Debug
  run: env  # Prints ALL environment variables including secrets

# Scenario 3 — Secret stored in repo history
git log --all -p | grep -i "password\|secret\|key\|token"
# Finds secrets even after they're "deleted" in a later commit
```

---

## Detection

```bash
# Scan your repo history for secrets (run locally before pushing)
# Install trufflehog
pip install trufflehog

trufflehog git file://. --only-verified
trufflehog github --repo https://github.com/sharanch/my-app

# Install gitleaks
brew install gitleaks  # or download binary

gitleaks detect --source . --verbose
gitleaks detect --source . --log-opts="--all"  # scan full git history

# Check if any secrets are currently in environment (CI debug)
# SAFE way — only print key names, not values
env | cut -d'=' -f1 | sort
```

---

## Fix — Use AWS Secrets Manager

### Store Secrets
```bash
# Store a database password
aws secretsmanager create-secret \
  --name prod/myapp/db-password \
  --description "Production DB password" \
  --secret-string '{"username":"admin","password":"my-secure-password"}'

# Store a plain string secret
aws secretsmanager create-secret \
  --name prod/myapp/api-key \
  --secret-string "sk-1234567890abcdef"

# Update an existing secret
aws secretsmanager put-secret-value \
  --secret-id prod/myapp/db-password \
  --secret-string '{"username":"admin","password":"new-rotated-password"}'
```

### Fetch Secrets in CI/CD Pipeline
```yaml
# GitHub Actions — fetch from Secrets Manager at runtime
- name: Get secrets from AWS Secrets Manager
  run: |
    DB_PASSWORD=$(aws secretsmanager get-secret-value \
      --secret-id prod/myapp/db-password \
      --query 'SecretString' \
      --output text | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")

    # Mask the value so it never appears in logs
    echo "::add-mask::$DB_PASSWORD"

    # Export for subsequent steps
    echo "DB_PASSWORD=$DB_PASSWORD" >> $GITHUB_ENV
```

### Fetch Secrets in Application Code
```bash
# Python — fetch at startup, not hardcoded
python3 - <<'EOF'
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager', region_name='ap-south-1')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

db_creds = get_secret('prod/myapp/db-password')
db_password = db_creds['password']
# Never printed, never hardcoded
EOF
```

---

## Fix — Use AWS Systems Manager Parameter Store (Cheaper)

```bash
# Store a secret (SecureString = encrypted with KMS)
aws ssm put-parameter \
  --name /prod/myapp/db-password \
  --value "my-secure-password" \
  --type SecureString \
  --key-id alias/aws/ssm

# Fetch in pipeline
DB_PASSWORD=$(aws ssm get-parameter \
  --name /prod/myapp/db-password \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text)

# List all parameters for your app
aws ssm describe-parameters \
  --parameter-filters "Key=Path,Values=/prod/myapp/" \
  --query 'Parameters[*].[Name,Type,LastModifiedDate]' \
  --output table
```

---

## Prevent Secrets from Entering Logs

```yaml
# GitHub Actions — mask dynamically fetched values
- name: Fetch and mask secret
  run: |
    SECRET=$(aws secretsmanager get-secret-value \
      --secret-id prod/myapp/api-key --query 'SecretString' --output text)
    echo "::add-mask::$SECRET"
    echo "API_KEY=$SECRET" >> $GITHUB_ENV

# NEVER do this:
- run: echo $API_KEY          # Prints secret to log
- run: env                    # Prints all env vars including secrets
- run: cat .env               # Prints secret file
- run: set -x && ./deploy.sh  # xtrace mode prints every variable expansion
```

---

## Enable Automatic Secret Rotation

```bash
# Enable automatic rotation for DB credentials (every 30 days)
aws secretsmanager rotate-secret \
  --secret-id prod/myapp/db-password \
  --rotation-rules AutomaticallyAfterDays=30

# Check rotation status
aws secretsmanager describe-secret \
  --secret-id prod/myapp/db-password \
  --query '[RotationEnabled,LastRotatedDate,NextRotationDate]'
```

---

## Checklist

- [ ] No secrets in source code or `.env` files committed to git
- [ ] `gitleaks` or `trufflehog` in pre-commit hooks
- [ ] All pipeline secrets fetched from Secrets Manager or Parameter Store at runtime
- [ ] Dynamic secrets masked with `::add-mask::` in GitHub Actions logs
- [ ] `env` and `set -x` not used in pipeline steps
- [ ] Secret rotation enabled (30–90 day cycle)
- [ ] IAM permissions for pipelines scoped to `secretsmanager:GetSecretValue` on specific secret ARNs only
