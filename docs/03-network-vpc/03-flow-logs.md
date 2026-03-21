# VPC Flow Logs — Network Visibility and Threat Detection

## The Problem

Without flow logs you are blind. You cannot detect data exfiltration, lateral movement, port scanning, or unexpected connections. When an incident happens, you have no forensic evidence.

---

## What Flow Logs Capture

```
<version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport>
<dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>

Example — accepted connection:
2 123456789 eni-0abc123 10.0.1.5 10.0.2.10 54321 5432 6 15 1200 1609459200 1609459260 ACCEPT OK

Example — rejected connection (port scan or unauthorized access attempt):
2 123456789 eni-0abc123 185.220.101.5 10.0.1.5 45678 22 6 1 40 1609459200 1609459210 REJECT OK
```

---

## Detection — Check if Flow Logs Are Enabled

```bash
# Check flow logs for a specific VPC
aws ec2 describe-flow-logs \
  --filter "Name=resource-id,Values=vpc-0123456789abcdef0" \
  --query 'FlowLogs[*].[FlowLogId,ResourceId,TrafficType,LogDestinationType,DeliverLogsStatus]' \
  --output table

# Check all flow logs in the account
aws ec2 describe-flow-logs \
  --query 'FlowLogs[*].[ResourceId,TrafficType,LogDestinationType,DeliverLogsStatus]' \
  --output table

# AWS Config rule — flag VPCs without flow logs
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "vpc-flow-logs-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "VPC_FLOW_LOGS_ENABLED"
    }
  }'
```

---

## Fix — Enable Flow Logs

### To CloudWatch Logs
```bash
# Create IAM role for flow logs to write to CloudWatch
aws iam create-role \
  --role-name VPCFlowLogsRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name VPCFlowLogsRole \
  --policy-name FlowLogsPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    }]
  }'

# Enable flow logs to CloudWatch
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::123456789:role/VPCFlowLogsRole
```

### To S3 (Cheaper for Long-term Retention)
```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::my-flow-logs-bucket/vpc-logs/ \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
```

---

## Querying Flow Logs with CloudWatch Insights

```bash
# Find top talkers — which IPs are sending the most traffic
aws logs start-query \
  --log-group-name /aws/vpc/flowlogs \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields srcaddr, dstaddr, bytes
    | stats sum(bytes) as totalBytes by srcaddr, dstaddr
    | sort totalBytes desc
    | limit 20'

# Find all REJECTED connections — potential port scanning or intrusion attempts
aws logs start-query \
  --log-group-name /aws/vpc/flowlogs \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields srcaddr, dstaddr, dstport, action
    | filter action = "REJECT"
    | stats count(*) as attempts by srcaddr, dstport
    | sort attempts desc
    | limit 20'

# Detect potential data exfiltration — large outbound transfers
aws logs start-query \
  --log-group-name /aws/vpc/flowlogs \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields srcaddr, dstaddr, bytes, dstport
    | filter bytes > 10000000
    | filter srcaddr like /^10\./
    | sort bytes desc'

# Get query results
aws logs get-query-results --query-id <query-id>
```

---

## CloudWatch Alarms on Flow Log Patterns

```bash
# Create metric filter — count rejected SSH connections
aws logs put-metric-filter \
  --log-group-name /aws/vpc/flowlogs \
  --filter-name RejectedSSH \
  --filter-pattern '[version, account, eni, source, destination, srcport, destport="22", protocol, packets, bytes, windowstart, windowend, action="REJECT", flowlogstatus]' \
  --metric-transformations \
    metricName=RejectedSSHCount,metricNamespace=VPCFlowLogs,metricValue=1

# Alarm if more than 10 rejected SSH attempts in 5 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name HighRejectedSSH \
  --alarm-description "Port scanning or SSH brute force detected" \
  --metric-name RejectedSSHCount \
  --namespace VPCFlowLogs \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns::123456789:SecurityAlerts
```

---

## Checklist

- [ ] Flow logs enabled on all VPCs — traffic type ALL
- [ ] Logs shipping to CloudWatch for querying + S3 for long-term retention
- [ ] Log retention policy set (e.g., 90 days CloudWatch, 1 year S3)
- [ ] CloudWatch Insights queries saved for common investigation patterns
- [ ] Metric filters + alarms on rejected connections, port scans, large transfers
- [ ] GuardDuty enabled — it analyzes flow logs automatically for threats
