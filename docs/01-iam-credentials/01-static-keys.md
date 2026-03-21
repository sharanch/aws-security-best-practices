# Static Access Keys — Risks and Elimination

## The Problem

Static access keys (`AKIA...`) are permanent credentials — they never expire unless manually rotated or deleted. A leaked key gives an attacker indefinite access to your AWS account.

---

## How Keys Get Leaked

### 1. Committed to Git
```bash
# Common patterns bots scan for on GitHub within seconds of a push
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...

# Found in: .env files, application configs, hardcoded in source
```

### 2. Exposed in CI/CD Logs
```bash
# Accidentally printed in a build step
echo "Deploying with key: $AWS_ACCESS_KEY_ID"

# Or passed as a plain argument instead of a secret
aws s3 cp file.txt s3://bucket --access-key AKIA... --secret-key ...
```

### 3. Sitting in ~/.aws/credentials on a Compromised Laptop
```bash
# Any malware or attacker with shell access reads this instantly
cat ~/.aws/credentials

[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

---

## Detection — Audit Your Account

```bash
# 1. Generate a credential report for all IAM users
aws iam generate-credential-report

# 2. Download and decode it
aws iam get-credential-report \
  --query 'Content' \
  --output text | base64 -d > credential-report.csv

# 3. Find users with active access keys
cat credential-report.csv | cut -d',' -f1,9,14 | grep 'true'
# Columns: username, access_key_1_active, access_key_2_active

# 4. Check when keys were last used
aws iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE

# 5. List all access keys for a specific user
aws iam list-access-keys --user-name sharan
```

---

## Detection — Check for Leaked Keys

```bash
# Check if a key has been used recently from an unexpected region
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,EventName,AwsRegion,SourceIPAddress]' \
  --output table

# Check root account access key status (should always be 0)
aws iam get-account-summary \
  --query 'SummaryMap.AccountAccessKeysPresent'
```

---

## Immediate Response — Key Compromised

```bash
# Step 1 — Deactivate immediately (do NOT delete yet — needed for forensics)
aws iam update-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive \
  --user-name compromised-user

# Step 2 — Attach a deny-all policy to kill all active sessions
aws iam put-user-policy \
  --user-name compromised-user \
  --policy-name EmergencyDenyAll \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'

# Step 3 — Check what the key did via CloudTrail
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --query 'Events[*].[EventTime,EventName,AwsRegion,SourceIPAddress,Username]' \
  --output table

# Step 4 — Check for backdoor users or keys created
aws iam list-users --query 'Users[*].[UserName,CreateDate]' --output table
aws iam list-roles --query 'Roles[*].[RoleName,CreateDate]' --output table

# Step 5 — After forensics, delete the key
aws iam delete-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --user-name compromised-user
```

---

## Prevention — Eliminate Static Keys

### Option 1: Enforce key rotation via IAM policy
```bash
# Deny API calls if key is older than 90 days
# Add this to your IAM policy
cat <<'EOF'
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "NumericGreaterThan": {
      "aws:credentials-age": "90"
    }
  }
}
EOF
```

### Option 2: Move to IAM Identity Center (recommended)
```bash
# Install AWS CLI v2 with SSO support
aws configure sso

# Login — opens browser, MFA prompt, returns temp credentials
aws sso login --profile my-profile

# Credentials auto-expire (1-8 hrs), no static keys needed
aws sts get-caller-identity --profile my-profile
```

### Option 3: Use git-secrets to prevent accidental commits
```bash
# Install git-secrets
git secrets --install
git secrets --register-aws

# Now any commit containing AWS key patterns is blocked
git commit -m "add config"
# ERROR: Potential AWS access key found
```

---

## Checklist

- [ ] Root account has zero active access keys
- [ ] All IAM user keys rotated within last 90 days
- [ ] Keys unused for 90+ days are deactivated/deleted
- [ ] `git-secrets` or `trufflehog` installed in pre-commit hooks
- [ ] CloudTrail enabled to log all key usage
- [ ] GuardDuty enabled — detects anomalous key usage automatically
- [ ] Working toward full elimination via IAM Identity Center
