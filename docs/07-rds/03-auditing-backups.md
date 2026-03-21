# RDS Auditing, Backups, and Forensics

## Attack Scenarios

### Scenario 1 — No Audit Logs, Attacker's Queries Invisible
```sql
-- Attacker dumps entire customer table
SELECT * FROM customers;
-- Exports 2 million records to a file

-- Without pgaudit or general_log enabled:
-- Zero trace in any log — you'll never know what was queried
-- Only visible if you had network-level capture (VPC flow logs show bytes, not queries)
```

### Scenario 2 — Automated Backups Disabled, Ransomware Succeeds
```bash
# Attacker drops all tables
# Without automated backups: data is permanently gone

# Common scenario: dev turns off backups to save cost, forgets to re-enable in prod
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --backup-retention-period 0   # This disables automated backups entirely
```

### Scenario 3 — Snapshot Shared to Wrong Account
```bash
# Engineer sharing a snapshot for a vendor to debug an issue
# Accidentally shares to the wrong account ID
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier prod-db-snapshot \
  --attribute-name restore \
  --values-to-add 999999999999  # Typo in account ID — shared with stranger
# Stranger restores your entire production database
```

---

## Detection — Enable Audit Logging

```bash
# PostgreSQL — enable pgaudit
aws rds create-db-parameter-group \
  --db-parameter-group-name pgaudit-params \
  --db-parameter-group-family postgres15 \
  --description "Enable pgaudit logging"

aws rds modify-db-parameter-group \
  --db-parameter-group-name pgaudit-params \
  --parameters \
    'ParameterName=shared_preload_libraries,ParameterValue=pgaudit,ApplyMethod=pending-reboot' \
    'ParameterName=pgaudit.log,ParameterValue=all,ApplyMethod=immediate' \
    'ParameterName=log_connections,ParameterValue=1,ApplyMethod=immediate' \
    'ParameterName=log_disconnections,ParameterValue=1,ApplyMethod=immediate'

# Enable CloudWatch log export for audit logs
aws rds modify-db-instance \
  --db-instance-identifier mydb \
  --cloudwatch-logs-export-configuration 'EnableLogTypes=["postgresql","upgrade"]' \
  --apply-immediately

# MySQL — enable general log and audit log
aws rds modify-db-parameter-group \
  --db-parameter-group-name mysql-audit-params \
  --parameters \
    'ParameterName=general_log,ParameterValue=1,ApplyMethod=immediate' \
    'ParameterName=slow_query_log,ParameterValue=1,ApplyMethod=immediate' \
    'ParameterName=long_query_time,ParameterValue=2,ApplyMethod=immediate'
```

---

## Query Audit Logs for Forensics

```bash
# After a suspected breach — query PostgreSQL audit logs in CloudWatch
aws logs start-query \
  --log-group-name /aws/rds/instance/mydb/postgresql \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, @message
    | filter @message like /SELECT/
    | filter @message like /customers/
    | sort @timestamp asc
    | limit 100'

# Find all connections from unexpected IPs
aws logs start-query \
  --log-group-name /aws/rds/instance/mydb/postgresql \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, @message
    | filter @message like /connection received/
    | parse @message "host=* " as source_ip
    | stats count(*) by source_ip
    | sort count desc'

# Find large data exports (slow queries touching many rows)
aws logs start-query \
  --log-group-name /aws/rds/instance/mydb/postgresql \
  --start-time $(date -d '24 hours ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, @message
    | filter @message like /duration/
    | parse @message "duration: * ms" as duration_ms
    | filter duration_ms > 5000
    | sort duration_ms desc'
```

---

## Backup and Recovery

```bash
# Verify automated backups are configured correctly
aws rds describe-db-instances \
  --db-instance-identifier mydb \
  --query 'DBInstances[*].[DBInstanceIdentifier,BackupRetentionPeriod,PreferredBackupWindow,LatestRestorableTime]' \
  --output table

# List all automated snapshots for an instance
aws rds describe-db-snapshots \
  --db-instance-identifier mydb \
  --snapshot-type automated \
  --query 'DBSnapshots[*].[DBSnapshotIdentifier,SnapshotCreateTime,Status]' \
  --output table

# Point-in-time recovery — restore to 1 hour before attack
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier mydb \
  --target-db-instance-identifier mydb-recovered \
  --restore-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)

# Restore from a specific manual snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier mydb-restored \
  --db-snapshot-identifier mydb-clean-snapshot \
  --db-subnet-group-name private-subnets \
  --no-publicly-accessible

# Audit snapshot access history
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=mydb-snapshot \
  --query 'Events[*].[EventTime,EventName,Username,SourceIPAddress]' \
  --output table
```

---

## Checklist

- [ ] pgaudit or MySQL general log enabled and shipping to CloudWatch
- [ ] Log connections and disconnections enabled
- [ ] CloudWatch log retention set to 90 days minimum for DB logs
- [ ] Automated backups enabled with 7+ day retention period
- [ ] Point-in-time recovery tested — know your RTO/RPO
- [ ] Deletion protection enabled — prevents accidental or malicious instance deletion
- [ ] Manual snapshots taken before major changes or deployments
- [ ] Snapshot sharing audited — only explicitly approved account IDs allowed
- [ ] CloudWatch alarms on failed login attempts and unusual query volumes
