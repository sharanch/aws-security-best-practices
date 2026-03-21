# IAM Identity Center (SSO)

## Why Identity Center

Static access keys (`AKIA...`) are permanent, easy to leak, and bypass MFA. IAM Identity Center replaces them with short-lived credentials vended per-session — after the user authenticates with MFA.

```
Static Keys                     Identity Center
───────────                     ───────────────
AKIA... (never expires)    vs   ASIA... (expires in 1-8 hrs)
No MFA on API calls             MFA baked into login
~/.aws/credentials file         Cached temp creds only
One breach = permanent access   Breach = useless after TTL
```

---

## How It Works

```
Developer runs: aws sso login
        │
        ▼
Browser opens → company SSO page (Okta / Azure AD / native)
        │
        ▼
Developer authenticates: username + password + MFA
        │
        ▼
Identity Center validates with your IdP
        │
        ▼
STS issues temporary credentials (AccessKeyId ASIA..., SessionToken)
        │
        ▼
AWS CLI/SDK uses them transparently
        │
        ▼
Credentials expire → re-login required (no manual rotation ever)
```

---

## Setup

### Step 1 — Enable Identity Center
```bash
# Enable via console or CLI (one-time, per organization)
aws sso-admin list-instances
# If empty, enable Identity Center in AWS Console under IAM Identity Center

# List your Identity Center instance
aws sso-admin list-instances \
  --query 'Instances[*].[InstanceArn,IdentityStoreId]' \
  --output table
```

### Step 2 — Configure AWS CLI for SSO
```bash
# Interactive setup
aws configure sso

# It will ask:
# SSO start URL: https://mycompany.awsapps.com/start
# SSO region: ap-south-1
# Account ID and role to use

# This writes to ~/.aws/config (no secrets in this file)
cat ~/.aws/config
# [profile dev-account]
# sso_session = my-sso
# sso_account_id = 123456789012
# sso_role_name = DeveloperAccess
# region = ap-south-1
#
# [sso-session my-sso]
# sso_start_url = https://mycompany.awsapps.com/start
# sso_region = ap-south-1
# sso_registration_scopes = sso:account:access
```

### Step 3 — Login and Use
```bash
# Authenticate (opens browser, MFA prompt)
aws sso login --profile dev-account

# Use AWS normally — credentials handled transparently
aws s3 ls --profile dev-account
aws ec2 describe-instances --profile dev-account

# Set default profile to avoid --profile every time
export AWS_PROFILE=dev-account

# Verify what identity you are using
aws sts get-caller-identity
# {
#   "UserId": "AROA...:sharan@company.com",
#   "Account": "123456789012",
#   "Arn": "arn:aws:sts::123456789012:assumed-role/DeveloperAccess/sharan@company.com"
# }

# Check when your session expires
aws sts get-caller-identity 2>&1 || echo "Session expired — run aws sso login"
```

---

## Credential Lifecycle
```bash
# Temp credentials are cached here (auto-managed by CLI)
ls ~/.aws/sso/cache/       # SSO tokens
ls ~/.aws/cli/cache/       # STS credentials

# View the cached credentials (for debugging only)
cat ~/.aws/cli/cache/*.json | python3 -m json.tool
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "SessionToken": "...",
#   "Expiration": "2024-01-01T08:00:00Z"   <-- auto-expires
# }

# Logout — invalidates session
aws sso logout --profile dev-account
```

---

## Using SSO Credentials in Scripts and SDKs

```bash
# boto3 — automatically picks up SSO profile
python3 - <<'EOF'
import boto3

session = boto3.Session(profile_name='dev-account')
s3 = session.client('s3')
buckets = s3.list_buckets()
print([b['Name'] for b in buckets['Buckets']])
EOF

# If session is expired, boto3 raises botocore.exceptions.UnauthorizedSSOTokenError
# Handle it:
python3 - <<'EOF'
import boto3
from botocore.exceptions import UnauthorizedSSOTokenError

try:
    session = boto3.Session(profile_name='dev-account')
    sts = session.client('sts')
    print(sts.get_caller_identity())
except UnauthorizedSSOTokenError:
    print("SSO session expired. Run: aws sso login --profile dev-account")
EOF
```

---

## Assign Permissions to Users/Groups

```bash
# List permission sets (roles users can assume)
aws sso-admin list-permission-sets \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --query 'PermissionSets' --output text

# Assign a permission set to a group for an account
aws sso-admin create-account-assignment \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --target-id 123456789012 \
  --target-type AWS_ACCOUNT \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx \
  --principal-type GROUP \
  --principal-id group-id-from-identity-store

# List all assignments for an account
aws sso-admin list-account-assignments \
  --instance-arn arn:aws:sso:::instance/ssoins-xxx \
  --account-id 123456789012 \
  --permission-set-arn arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx
```

---

## Checklist

- [ ] IAM Identity Center enabled in AWS Organizations
- [ ] All human users access AWS via SSO — no static keys
- [ ] MFA enforced at the IdP level (Okta / Azure AD / native)
- [ ] Permission sets follow least privilege — scoped per team/role
- [ ] Root account has no active access keys
- [ ] Existing static key users have a migration plan to SSO
- [ ] SDK/scripts updated to use `boto3.Session(profile_name=...)` with SSO profiles
