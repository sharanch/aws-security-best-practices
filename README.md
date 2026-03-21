# AWS Security Best Practices

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A practical reference for DevOps and SRE engineers covering AWS security across the four most critical domains. Each section includes real attack scenarios, CLI commands, and actionable mitigations.

> **Audience:** Mid-level DevOps/SRE engineers  
> **Style:** Scenario-driven — understand the attack, then fix it

---

## Sections

| # | Topic | What's Covered |
|---|-------|----------------|
| 01 | [IAM & Credentials](./docs/01-iam-credentials/README.md) | Static keys, role abuse, privilege escalation, Identity Center |
| 02 | [EC2 & Compute Security](./docs/02-ec2-compute/README.md) | IMDS, instance roles, SSH hardening, IMDSv2 |
| 03 | [Network & VPC Security](./docs/03-network-vpc/README.md) | Security groups, VPC endpoints, NACLs, flow logs |
| 04 | [CI/CD Pipeline Security](./docs/04-cicd-pipeline/README.md) | OIDC, secrets management, pipeline hardening |
| 05 | [S3 Security](./docs/05-s3/README.md) | Public access, bucket policies, encryption, ransomware defense |
| 06 | [Lambda Security](./docs/06-lambda/README.md) | Execution roles, env var secrets, function URLs, supply chain |
| 07 | [RDS & Database Security](./docs/07-rds/README.md) | Public access, IAM auth, encryption, audit logging |
| 08 | [Detection & Response](./docs/08-detection/README.md) | CloudTrail hardening, GuardDuty alerting, Security Hub |

---

## Core Philosophy

```
Assume breach will happen.
Design so that when it does:
  - Blast radius is minimal
  - Detection is immediate
  - Recovery is fast
```

Every recommendation in this repo follows three principles:

- **Least Privilege** — grant only what is needed, nothing more
- **Defense in Depth** — no single control is enough; layer them
- **Assume Breach** — monitor, alert, and have a response plan

---

## Audit Scripts

Run these against any AWS account to get an instant security posture snapshot:

```bash
# Clone the repo and run all audits
git clone https://github.com/sharanch/aws-security-best-practices
cd aws-security-best-practices/scripts

chmod +x *.sh

# IAM — root keys, MFA, admin access, GuardDuty, CloudTrail
./audit-iam.sh --profile my-profile --region ap-south-1

# EC2 — IMDSv2, public IPs, open ports, EBS encryption, SSM readiness
./audit-ec2.sh --profile my-profile --region ap-south-1

# Network — VPC flow logs, VPC endpoints, security groups, S3 public access
./audit-network.sh --profile my-profile --region ap-south-1

# S3 + RDS + Lambda — bucket policies, encryption, public RDS, env var secrets
./audit-s3-rds.sh --profile my-profile --region ap-south-1
```

Scripts exit with code `1` if critical issues are found — safe to use in CI/CD gates.

---

## Quick Reference — Most Critical Controls

```bash
# 1. Check if root account has active access keys (should return 0)
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'

# 2. List all IAM users with active access keys
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I{} aws iam list-access-keys --user-name {}

# 3. Check if MFA is enabled for all IAM users
aws iam generate-credential-report && \
aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | cut -d',' -f1,4,8 | grep ',false'

# 4. Check IMDSv2 enforcement across all EC2 instances
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId, MetadataOptions.HttpTokens]' \
  --output table

# 5. Check if CloudTrail is enabled
aws cloudtrail describe-trails --query 'trailList[*].[Name,IsMultiRegionTrail]' --output table
```

---

## Repo Structure

```
aws-security-best-practices/
├── README.md
├── LICENSE
├── docs/
│   ├── 01-iam-credentials/
│   │   ├── README.md
│   │   ├── 01-static-keys.md
│   │   ├── 02-role-abuse.md
│   │   ├── 03-privilege-escalation.md
│   │   └── 04-identity-center.md
│   ├── 02-ec2-compute/
│   │   ├── README.md
│   │   ├── 01-imdsv2.md
│   │   ├── 02-instance-roles.md
│   │   └── 03-ssh-hardening.md
│   ├── 03-network-vpc/
│   │   ├── README.md
│   │   ├── 01-security-groups.md
│   │   ├── 02-vpc-endpoints.md
│   │   └── 03-flow-logs.md
│   ├── 04-cicd-pipeline/
│   │   ├── README.md
│   │   ├── 01-oidc-auth.md
│   │   ├── 02-secrets-management.md
│   │   └── 03-pipeline-hardening.md
│   ├── 05-s3/
│   │   ├── README.md
│   │   ├── 01-public-access.md
│   │   ├── 02-bucket-policies.md
│   │   └── 03-data-protection.md
│   ├── 06-lambda/
│   │   ├── README.md
│   │   ├── 01-execution-roles.md
│   │   ├── 02-env-vars-secrets.md
│   │   └── 03-function-hardening.md
│   ├── 07-rds/
│   │   ├── README.md
│   │   ├── 01-public-access.md
│   │   ├── 02-auth-encryption.md
│   │   └── 03-auditing-backups.md
│   └── 08-detection/
│       ├── README.md
│       ├── 01-cloudtrail.md
│       ├── 02-guardduty.md
│       └── 03-security-hub.md
└── scripts/
    ├── audit-iam.sh
    ├── audit-ec2.sh
    ├── audit-network.sh
    └── audit-s3-rds.sh
```

---

## License

This project is licensed under the [MIT License](./LICENSE) — free to use, share, and adapt with attribution.

---

## Contributing

Found a gap or a new attack vector? PRs welcome. Please follow the existing format:
1. Explain the attack scenario first
2. Show the CLI commands to detect it
3. Show the fix with CLI commands
4. Add a summary checklist at the end
