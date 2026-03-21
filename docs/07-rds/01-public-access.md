# RDS Public Access — Exposure and Network Hardening

## Attack Scenarios

### Scenario 1 — Publicly Accessible RDS with Weak Password
```bash
# RDS instance created with PubliclyAccessible=true (common mistake in dev)
# Security group has port 5432 open to 0.0.0.0/0

# Attacker discovers it via Shodan, Censys, or AWS IP range scanning
# Attempts brute force or credential stuffing with common passwords

# From any machine on the internet:
psql -h mydb.abc123.ap-south-1.rds.amazonaws.com \
  -U admin -d myapp -W
# Enter password: password123 — database dumped

# Or automated scan:
nmap -sV -p 5432 mydb.abc123.ap-south-1.rds.amazonaws.com
# 5432/tcp open postgresql PostgreSQL DB
```

### Scenario 2 — Security Group Too Broad
```bash
# RDS in a private subnet BUT security group allows 0.0.0.0/0 on DB port
# Any compromised EC2 in ANY subnet can reach the database

# Check what's in the security group attached to RDS
aws ec2 describe-security-groups \
  --group-ids sg-rds-sg \
  --query 'SecurityGroups[*].IpPermissions[?FromPort==`5432`]'
# Returns: cidr 0.0.0.0/0 — all EC2 instances and even internet can reach it
```

### Scenario 3 — RDS Snapshot Made Public
```bash
# Attacker who compromised an admin role shares your RDS snapshot publicly
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier mydb-snapshot-2024 \
  --attribute-name restore \
  --values-to-add all   # Any AWS account can now restore your DB

# Or attacker restores your snapshot to their own account
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier attacker-restored-db \
  --db-snapshot-identifier arn:aws:rds:ap-south-1:123456789:snapshot:mydb-snapshot
# Your entire database is now in attacker's account
```

---

## Detection

```bash
# 1. Find publicly accessible RDS instances
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,DBInstanceClass,Endpoint.Address]' \
  --output table

# 2. Find RDS instances not in a private subnet
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,DBSubnetGroup.DBSubnetGroupName,MultiAZ]' \
  --output table

# Check each subnet to see if it has a route to an internet gateway
aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=subnet-id" \
  --query 'RouteTables[*].Routes[?GatewayId!=null && contains(GatewayId, `igw-`)]'

# 3. Find RDS security groups allowing broad DB port access
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,VpcSecurityGroups[*].VpcSecurityGroupId]' \
  --output text | while read -r db_id sg_id; do
    [[ -z "$sg_id" ]] && continue
    open=$(aws ec2 describe-security-groups \
      --group-ids "$sg_id" \
      --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`] && (FromPort==`5432` || FromPort==`3306` || FromPort==`1433`)]' \
      --output text 2>/dev/null || echo "")
    [[ -n "$open" ]] && echo "CRITICAL: RDS $db_id security group $sg_id has DB port open to 0.0.0.0/0"
  done

# 4. Find publicly shared RDS snapshots
aws rds describe-db-snapshots \
  --snapshot-type manual \
  --query 'DBSnapshots[*].DBSnapshotIdentifier' --output text | tr '\t' '\n' | \
  while read -r snapshot; do
    attrs=$(aws rds describe-db-snapshot-attributes \
      --db-snapshot-identifier "$snapshot" \
      --query 'DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName==`restore`].AttributeValues' \
      --output text 2>/dev/null || echo "")
    [[ "$attrs" == *"all"* ]] && echo "CRITICAL: Snapshot $snapshot is PUBLIC"
  done

# 5. AWS Config rules
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "rds-instance-public-access-check",
    "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"}
  }'

aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "rds-snapshots-public-prohibited",
    "Source": {"Owner": "AWS", "SourceIdentifier": "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"}
  }'
```

---

## Fix

```bash
# Fix 1: Disable public accessibility
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --no-publicly-accessible \
  --apply-immediately

# Fix 2: Move to private subnet group
# Create a subnet group with only private subnets
aws rds create-db-subnet-group \
  --db-subnet-group-name private-subnets \
  --db-subnet-group-description "Private subnets only" \
  --subnet-ids subnet-private-1a subnet-private-1b subnet-private-1c

# Fix 3: Tighten RDS security group — only allow from app tier SG
# Remove broad rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-rds-sg \
  --protocol tcp \
  --port 5432 \
  --cidr 0.0.0.0/0

# Allow only from application server security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-rds-sg \
  --protocol tcp \
  --port 5432 \
  --source-group sg-app-sg

# Fix 4: Remove public sharing on snapshots
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier mydb-snapshot \
  --attribute-name restore \
  --values-to-remove all

# Fix 5: Encrypt an existing unencrypted RDS instance
# (Must snapshot → copy with encryption → restore)
aws rds create-db-snapshot \
  --db-instance-identifier mydb \
  --db-snapshot-identifier mydb-unencrypted-snapshot

aws rds copy-db-snapshot \
  --source-db-snapshot-identifier mydb-unencrypted-snapshot \
  --target-db-snapshot-identifier mydb-encrypted-snapshot \
  --kms-key-id arn:aws:kms:ap-south-1:123456789:key/your-key-id

aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier mydb-encrypted \
  --db-snapshot-identifier mydb-encrypted-snapshot
```

---

## Checklist

- [ ] All RDS instances have `PubliclyAccessible: false`
- [ ] All RDS instances in private subnets (no IGW route in subnet route table)
- [ ] RDS security groups allow only specific application tier security groups
- [ ] No manual snapshots are publicly shared (`restore` attribute ≠ `all`)
- [ ] Automated snapshot encryption enabled
- [ ] AWS Config rules `RDS_INSTANCE_PUBLIC_ACCESS_CHECK` and `RDS_SNAPSHOTS_PUBLIC_PROHIBITED` active
- [ ] Cross-account snapshot sharing limited to explicitly approved account IDs only
