# Security Groups — Hardening Inbound and Outbound Rules

## The Problem

Security groups default to deny-all inbound and allow-all outbound. Misconfigured groups open the attack surface — allowing attackers to probe services or exfiltrate data freely.

---

## Common Mistakes

```bash
# Mistake 1: Open SSH/RDP to the entire internet
# From port 22 / cidr 0.0.0.0/0

# Mistake 2: Outbound allow-all — lets compromised instance call anything
# To port all / protocol all / cidr 0.0.0.0/0

# Mistake 3: Using a single security group for all resources
# One misconfiguration = all resources exposed

# Mistake 4: Unused rules left from old workloads
# Old ports still open, nobody knows what uses them
```

---

## Detection — Audit Security Groups

```bash
# Find security groups with inbound rules open to 0.0.0.0/0
aws ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].
           [GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]' \
  --output json

# Find all rules open on all ports (port -1)
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=-1" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table

# Find unused security groups (not attached to any resource)
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].GroupId' --output text | tr '\t' '\n' > /tmp/all-sgs.txt

aws ec2 describe-network-interfaces \
  --query 'NetworkInterfaces[*].Groups[*].GroupId' --output text | tr '\t' '\n' | sort -u > /tmp/used-sgs.txt

comm -23 <(sort /tmp/all-sgs.txt) /tmp/used-sgs.txt
# Output = unused security groups — candidates for deletion
```

---

## Fix — Apply Least Privilege to Security Groups

```bash
# Remove overly broad inbound rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Add a scoped rule — only your NAT gateway or bastion IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 443 \
  --source-group sg-alb-security-group  # Reference SG, not CIDR
# This allows only traffic from the ALB security group — nothing else

# Restrict outbound — only allow what the app actually needs
aws ec2 revoke-security-group-egress \
  --group-id sg-0123456789abcdef0 \
  --protocol all \
  --port all \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0  # HTTPS only outbound

aws ec2 authorize-security-group-egress \
  --group-id sg-0123456789abcdef0 \
  --protocol tcp \
  --port 5432 \
  --source-group sg-rds-security-group  # DB access only to RDS SG
```

---

## Recommended Security Group Architecture

```
Internet
    │
    ▼
[ALB Security Group]          Inbound: 443 from 0.0.0.0/0
    │                         Outbound: 8080 to App SG
    ▼
[App Security Group]          Inbound: 8080 from ALB SG only
    │                         Outbound: 5432 to DB SG, 443 to 0.0.0.0/0
    ▼
[DB Security Group]           Inbound: 5432 from App SG only
                              Outbound: nothing
```

```bash
# Create the layered security groups
# ALB SG
aws ec2 create-security-group \
  --group-name alb-sg \
  --description "ALB - public HTTPS only" \
  --vpc-id vpc-0123456789abcdef0

aws ec2 authorize-security-group-ingress \
  --group-id <alb-sg-id> --protocol tcp --port 443 --cidr 0.0.0.0/0

# App SG - only from ALB
aws ec2 create-security-group \
  --group-name app-sg \
  --description "App servers - from ALB only" \
  --vpc-id vpc-0123456789abcdef0

aws ec2 authorize-security-group-ingress \
  --group-id <app-sg-id> --protocol tcp --port 8080 \
  --source-group <alb-sg-id>

# DB SG - only from App
aws ec2 create-security-group \
  --group-name db-sg \
  --description "RDS - from app servers only" \
  --vpc-id vpc-0123456789abcdef0

aws ec2 authorize-security-group-ingress \
  --group-id <db-sg-id> --protocol tcp --port 5432 \
  --source-group <app-sg-id>
```

---

## Checklist

- [ ] No security group allows SSH (22) or RDP (3389) from `0.0.0.0/0`
- [ ] All SGs use source SG references instead of CIDRs where possible
- [ ] Outbound rules scoped — no allow-all outbound on production instances
- [ ] Unused security groups identified and deleted
- [ ] AWS Config rules: `INCOMING_SSH_DISABLED`, `RESTRICTED_INCOMING_TRAFFIC` active
- [ ] Security groups are per-tier (ALB, App, DB) — not shared across resources
