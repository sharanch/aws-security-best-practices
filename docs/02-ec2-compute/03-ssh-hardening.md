# SSH Hardening — Replace SSH with SSM Session Manager

## The Problem

Port 22 open to the internet is one of the most scanned ports globally. Static SSH keys on developer laptops get lost, stolen, or forgotten. Every key is a permanent door into your instances.

---

## The Better Approach — AWS Systems Manager Session Manager

No open ports. No SSH keys. Browser or CLI access through IAM authentication.

```
Traditional SSH                     SSM Session Manager
───────────────                     ───────────────────
Port 22 open in security group      Zero open inbound ports
Static SSH key on laptop            IAM identity + MFA
Key rotation is manual              No keys to rotate
No audit trail by default           Every session logged to CloudTrail + S3
Direct internet exposure needed     Works in private subnets
```

---

## Detection — Find Instances with Port 22 Exposed

```bash
# Find security groups with SSH open to the world
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
             "Name=ip-permission.to-port,Values=22" \
             "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
  --output table

# Find instances using those security groups
aws ec2 describe-instances \
  --filters "Name=instance.group-name,Values=<group-name>" \
  --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# AWS Config rule to flag port 22 open to 0.0.0.0/0
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "restricted-ssh",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "INCOMING_SSH_DISABLED"
    }
  }'
```

---

## Fix — Set Up SSM Session Manager

### Step 1 — Attach SSM Policy to Instance Role
```bash
# The instance needs this policy to communicate with SSM
aws iam attach-role-policy \
  --role-name MyEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# Verify the SSM agent is running on the instance
aws ssm describe-instance-information \
  --query 'InstanceInformationList[*].[InstanceId,PingStatus,LastPingDateTime]' \
  --output table
```

### Step 2 — Start a Session (No SSH Key Needed)
```bash
# Install Session Manager plugin for AWS CLI
# https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

# Open an interactive shell session
aws ssm start-session --target i-0123456789abcdef0

# Run a command without interactive session
aws ssm send-command \
  --instance-ids i-0123456789abcdef0 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["df -h","free -m"]' \
  --query 'Command.CommandId' \
  --output text

# Get command output
aws ssm get-command-invocation \
  --command-id <command-id> \
  --instance-id i-0123456789abcdef0 \
  --query '[StandardOutputContent,StandardErrorContent]'
```

### Step 3 — Enable Session Logging to S3
```bash
# Configure session logs — every command is recorded
aws ssm update-document \
  --name "SSM-SessionManagerRunShell" \
  --document-version "\$LATEST" \
  --content '{
    "schemaVersion": "1.0",
    "description": "SSM Session Manager preferences",
    "sessionType": "Standard_Stream",
    "inputs": {
      "s3BucketName": "my-ssm-session-logs",
      "s3EncryptionEnabled": true,
      "cloudWatchLogGroupName": "/ssm/sessions",
      "cloudWatchEncryptionEnabled": true
    }
  }'
```

### Step 4 — Remove Port 22 from Security Groups
```bash
# Revoke SSH access from the security group
aws ec2 revoke-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Verify no SSH rules remain
aws ec2 describe-security-groups \
  --group-ids sg-0123456789abcdef0 \
  --query 'SecurityGroups[*].IpPermissions[?FromPort==`22`]'
```

---

## If You Must Keep SSH — Harden It

```bash
# Use EC2 Instance Connect instead of static keys
# Sends a one-time SSH public key valid for 60 seconds
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-0123456789abcdef0 \
  --instance-os-user ec2-user \
  --ssh-public-key file://~/.ssh/id_rsa.pub \
  --availability-zone ap-south-1a

# Then SSH in within 60 seconds
ssh -i ~/.ssh/id_rsa ec2-user@<instance-ip>

# Restrict SSH to specific IPs only (not 0.0.0.0/0)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.10/32  # Your office IP only
```

---

## Checklist

- [ ] No security group has port 22 open to `0.0.0.0/0` or `::/0`
- [ ] SSM Agent installed and running on all EC2 instances
- [ ] `AmazonSSMManagedInstanceCore` policy attached to all instance roles
- [ ] Session Manager configured to log to S3 and CloudWatch
- [ ] AWS Config rule `INCOMING_SSH_DISABLED` active
- [ ] EC2 Instance Connect used for emergency access if SSH needed
- [ ] Instances in private subnets — no public IPs where possible
