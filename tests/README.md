# Local Audit Testing with Moto

Test all 4 audit scripts against a deliberately misconfigured AWS environment — no real AWS account needed. Uses [moto](https://github.com/getmoto/moto) to mock AWS services locally.

---

## How it works

```
test-all.sh
    │
    ├── starts moto_server on localhost:5000
    │
    ├── setup_vulnerable_env.py
    │     creates misconfigured resources:
    │     ├── IAM: users without MFA, admin access, dangerous trust policies
    │     ├── EC2: IMDSv1 instances, open SSH/RDP security groups, unencrypted EBS
    │     ├── Network: VPCs without flow logs, no VPC endpoints
    │     ├── S3: public buckets, no encryption, no versioning
    │     ├── RDS: publicly accessible, unencrypted, no backups
    │     └── Lambda: secrets in env vars, public URLs
    │
    ├── run-audit-local.sh
    │     runs all 4 audit scripts pointed at moto
    │     ├── audit-iam.sh
    │     ├── audit-ec2.sh
    │     ├── audit-network.sh
    │     └── audit-s3-rds.sh
    │
    └── stops moto_server
```

---

## Setup

```bash
# Install dependencies
pip install -r tests/requirements.txt --break-system-packages
```

---

## Run

```bash
# One command — does everything
bash tests/test-all.sh
```

Or step by step if you want to inspect resources between steps:

```bash
# Terminal 1 — start moto
moto_server -p 5000

# Terminal 2 — create resources
export AWS_ENDPOINT_URL=http://localhost:5000
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=ap-south-1
python3 tests/setup_vulnerable_env.py

# Inspect resources if you want
aws iam list-users
aws ec2 describe-instances
aws s3api list-buckets

# Run audits
bash tests/run-audit-local.sh
```

---

## Expected output

Every audit script should produce critical findings — that's the point:

```
[CRITICAL]  User 'test-admin-user' has AdministratorAccess attached directly
[CRITICAL]  Role 'test-dangerous-trust-role' has Principal: * in trust policy
[CRITICAL]  Instance i-xxxx (test-imdsv1-instance) has IMDSv1 enabled
[CRITICAL]  Security group sg-xxxx (test-open-ssh-sg) has SSH (22) open to 0.0.0.0/0
[CRITICAL]  RDS instance test-public-db is PUBLICLY ACCESSIBLE
[CRITICAL]  Bucket 'test-audit-public-bucket' is PUBLIC via bucket policy
[WARNING]   Lambda 'test-audit-lambda-secrets' has suspicious env vars: DB_PASSWORD, API_KEY
...
```

If you see these findings — the scripts work correctly.

---

## What each resource triggers

| Resource | Script | Finding |
|---|---|---|
| `test-no-mfa-user` | audit-iam | User has no MFA |
| `test-admin-user` | audit-iam | User has AdministratorAccess |
| `test-dangerous-trust-role` | audit-iam | Principal: * in trust policy |
| `test-imdsv1-instance` | audit-ec2 | IMDSv1 enabled |
| `test-admin-role-instance` | audit-ec2 | Instance has AdministratorAccess role |
| `test-open-ssh-sg` | audit-ec2 | SSH open to 0.0.0.0/0 |
| `test-open-rdp-sg` | audit-ec2 | RDP open to 0.0.0.0/0 |
| `test-all-traffic-sg` | audit-ec2 / audit-network | All traffic open |
| `test-unencrypted-ebs` | audit-ec2 | EBS not encrypted |
| `test-no-flowlogs-vpc` | audit-network | VPC has no flow logs |
| `test-audit-public-bucket` | audit-s3-rds | Bucket is public |
| `test-audit-noenc-bucket` | audit-s3-rds | No encryption, no versioning |
| `test-public-db` | audit-s3-rds | RDS publicly accessible, not encrypted |
| `test-audit-lambda-secrets` | audit-s3-rds | Secrets in env vars |
| `test-audit-lambda-public-url` | audit-s3-rds | Public Lambda URL |
