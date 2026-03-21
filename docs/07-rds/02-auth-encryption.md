# RDS Auth and Encryption — IAM Auth, Credential Rotation, and Encryption

## Attack Scenarios

### Scenario 1 — Static Master Password Never Rotated
```bash
# Master password set at DB creation, never changed
# Stored in a .env file, config file, or CI/CD variable
# One leak = permanent DB access until manually rotated

# Common places the password leaks:
# 1. Git history: git log --all -p | grep -i password
# 2. CI/CD logs: echo "Connecting to DB: $DB_URL"  (URL includes password)
# 3. Application crash dumps: exception includes connection string
# 4. Terraform state file: contains DB password in plaintext
cat terraform.tfstate | python3 -c "import sys,json; [print(r) for r in json.load(sys.stdin)['resources'] if 'password' in str(r)]"
```

### Scenario 2 — Connection Without SSL/TLS
```bash
# Application connects without enforcing SSL
# Traffic between app and RDS is plaintext on the network

# PostgreSQL without SSL:
psql "host=mydb.abc123.rds.amazonaws.com user=admin dbname=myapp"
# If someone intercepts traffic on the VPC (compromised host, misconfigured mirror):
# Full query contents, results, and credentials visible in plaintext
```

### Scenario 3 — Overly Broad DB User Permissions
```sql
-- Anti-pattern: application uses the master user for everything
-- Master user has SUPERUSER privileges in PostgreSQL
-- If compromised: attacker can read ALL tables, modify schema, add users

-- Checking who has what in PostgreSQL
SELECT usename, usesuper, usecreatedb, usecreaterole FROM pg_user;
-- If your app user shows usesuper=true — massive over-privilege
```

---

## Detection

```bash
# 1. Check if RDS instances have encryption at rest
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]' \
  --output table

# 2. Check if SSL is enforced (PostgreSQL)
aws rds describe-db-parameters \
  --db-parameter-group-name default.postgres15 \
  --query 'Parameters[?ParameterName==`rds.force_ssl`].[ParameterValue]' \
  --output text
# Should return: 1

# 3. Check if IAM DB auth is enabled
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,IAMDatabaseAuthenticationEnabled]' \
  --output table

# 4. Find RDS instances without automated backups
aws rds describe-db-instances \
  --query 'DBInstances[?BackupRetentionPeriod==`0`].[DBInstanceIdentifier]' \
  --output table

# 5. Check Secrets Manager for RDS credential rotation
aws secretsmanager list-secrets \
  --query 'SecretList[*].[Name,RotationEnabled,LastRotatedDate]' \
  --output table

# 6. AWS Config rules
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "rds-storage-encrypted",
    "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_STORAGE_ENCRYPTED"}
  }'
```

---

## Fix — IAM Database Authentication

```bash
# Fix 1: Enable IAM DB auth on the instance
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --enable-iam-database-authentication \
  --apply-immediately

# Fix 2: Create a DB user mapped to IAM (PostgreSQL)
# Connect to DB as master user and run:
# CREATE USER app_user WITH LOGIN;
# GRANT rds_iam TO app_user;

# Fix 3: Create IAM policy allowing DB connect with IAM token
aws iam create-policy \
  --policy-name RDSIAMConnect \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:ap-south-1:123456789:dbuser:db-ABCDEFGHIJKLMNOP/app_user"
    }]
  }'

# Fix 4: Connect using IAM token (Python)
python3 - <<'EOF'
import boto3
import psycopg2

rds_client = boto3.client('rds', region_name='ap-south-1')

# Generate auth token — valid for 15 minutes
token = rds_client.generate_db_auth_token(
    DBHostname='mydb.abc123.ap-south-1.rds.amazonaws.com',
    Port=5432,
    DBUsername='app_user'
)

# Connect using token as password
conn = psycopg2.connect(
    host='mydb.abc123.ap-south-1.rds.amazonaws.com',
    port=5432,
    database='myapp',
    user='app_user',
    password=token,
    sslmode='require'  # SSL required with IAM auth
)
print("Connected successfully")
conn.close()
EOF
```

---

## Fix — Encrypt and Rotate Credentials

```bash
# Fix 1: Store master password in Secrets Manager with auto-rotation
aws secretsmanager create-secret \
  --name prod/rds/mydb-master \
  --description "RDS master credentials" \
  --secret-string '{
    "username": "admin",
    "password": "InitialPassword123!",
    "engine": "postgres",
    "host": "mydb.abc123.ap-south-1.rds.amazonaws.com",
    "port": 5432,
    "dbname": "myapp"
  }'

# Enable automatic rotation every 30 days
aws secretsmanager rotate-secret \
  --secret-id prod/rds/mydb-master \
  --rotation-lambda-arn arn:aws:lambda:ap-south-1:123456789:function:SecretsManagerRDSPostgreSQLRotationSingleUser \
  --rotation-rules AutomaticallyAfterDays=30

# Fix 2: Enforce SSL on PostgreSQL RDS
aws rds create-db-parameter-group \
  --db-parameter-group-name force-ssl-params \
  --db-parameter-group-family postgres15 \
  --description "Force SSL connections"

aws rds modify-db-parameter-group \
  --db-parameter-group-name force-ssl-params \
  --parameters 'ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=immediate'

aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --db-parameter-group-name force-ssl-params \
  --apply-immediately

# Fix 3: Enable deletion protection
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --deletion-protection \
  --apply-immediately

# Fix 4: Set backup retention to 7+ days
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --backup-retention-period 7 \
  --apply-immediately
```

---

## Checklist

- [ ] All RDS instances have `StorageEncrypted: true`
- [ ] KMS customer-managed key used for RDS encryption (not default)
- [ ] IAM database authentication enabled — app uses token-based auth
- [ ] Master credentials stored in Secrets Manager with 30-day auto-rotation
- [ ] SSL/TLS enforced via parameter group (`rds.force_ssl=1` for PostgreSQL)
- [ ] Application DB user has minimal privileges — not master/superuser
- [ ] Deletion protection enabled on all production instances
- [ ] Automated backups set to 7+ day retention
- [ ] AWS Config rule `RDS_STORAGE_ENCRYPTED` active
