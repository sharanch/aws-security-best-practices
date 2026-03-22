# AWS Security Best Practices

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Sections](https://img.shields.io/badge/sections-8-3ddc84)
![Docs](https://img.shields.io/badge/docs-28-5ccfe6)
![Audit Scripts](https://img.shields.io/badge/audit%20scripts-4-ffb454)
![Tested with moto](https://img.shields.io/badge/tested%20with-moto-ff6b6b)

A production-grade AWS security reference for DevOps and SRE engineers. Real attack scenarios, detection CLI commands, hardening checklists, and runnable audit scripts — all verified against a local moto environment.

> **Audience:** Mid-level DevOps/SRE engineers  
> **Style:** Scenario-driven — understand the attack, detect it, fix it

---

## Sections

| # | Topic | What's Covered |
|---|-------|----------------|
| 01 | [IAM & Credentials](./docs/01-iam-credentials/README.md) | Static keys, role abuse, privilege escalation, Identity Center |
| 02 | [EC2 & Compute Security](./docs/02-ec2-compute/README.md) | IMDSv2 enforcement, instance roles, SSH → SSM Session Manager |
| 03 | [Network & VPC Security](./docs/03-network-vpc/README.md) | Security groups, VPC endpoints, flow logs |
| 04 | [CI/CD Pipeline Security](./docs/04-cicd-pipeline/README.md) | OIDC auth, secrets management, pipeline hardening |
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

Every doc follows the same structure:

1. **Attack scenario** — how it actually gets exploited
2. **Detection** — CLI commands to find it in a live account
3. **Fix** — CLI commands to remediate it
4. **Checklist** — what to verify before moving on

---

## Audit Scripts

Four shell scripts that assess a live AWS account and exit with code `1` on critical findings — safe to drop into CI/CD pipelines as security gates.

```bash
git clone https://github.com/sharanch/aws-security-best-practices
cd aws-security-best-practices
chmod +x scripts/*.sh

# IAM — root keys, MFA, admin access, dangerous trust policies, GuardDuty, CloudTrail
./scripts/audit-iam.sh --profile my-profile --region ap-south-1

# EC2 — IMDSv2, public IPs, open SSH/RDP, overprivileged roles, EBS encryption
./scripts/audit-ec2.sh --profile my-profile --region ap-south-1

# Network — VPC flow logs, VPC endpoints, security groups, S3 public access block
./scripts/audit-network.sh --profile my-profile --region ap-south-1

# S3 + RDS + Lambda — public buckets, encryption, public RDS, env var secrets, Lambda URLs
./scripts/audit-s3-rds.sh --profile my-profile --region ap-south-1
```

### What each script checks

| Script | Checks |
|--------|--------|
| `audit-iam.sh` | Root access keys, MFA per user, key age/usage, AdministratorAccess assignments, dangerous trust policies (`Principal: *`), password policy, Access Analyzer, CloudTrail, GuardDuty |
| `audit-ec2.sh` | IMDSv2 enforcement, public IPs, SSH/RDP/all-traffic SGs open to world, overprivileged instance roles, SSM Agent readiness, EBS encryption |
| `audit-network.sh` | VPC flow logs, S3/STS/DynamoDB VPC endpoints, default VPC presence, all-traffic inbound SGs, S3 account-level BPA, CloudTrail coverage |
| `audit-s3-rds.sh` | Account BPA settings, per-bucket encryption/versioning/logging, `Principal: *` bucket policies, RDS public access/encryption/IAM auth/deletion protection/backups, public snapshots, Lambda env var secrets, Lambda public URLs |

---

## Local Testing with Moto

Test all audit scripts locally against a deliberately misconfigured environment — no real AWS account needed.

```bash
# Requires: python3, aws-cli, curl
bash tests/test-all.sh
```

This single command:
1. Creates a Python venv at `tests/.venv` and installs moto + boto3
2. Starts a local moto server on port 5000
3. Creates misconfigured resources across IAM, EC2, VPC, S3, RDS, and Lambda
4. Runs all 4 audit scripts against the mock environment
5. Prints findings and stops the server

### Verified output

```
══════════════════════════════════════════
  OVERALL RESULTS
══════════════════════════════════════════
  FAILED  IAM Security Audit      — 5 critical, 3 warnings
  FAILED  EC2 Security Audit      — 4 critical, 5 warnings
  FAILED  Network Security Audit  — 4 critical, 6 warnings
  FAILED  S3 + RDS + Lambda Audit — 7 critical, 16 warnings

  Total critical: 20
  Total warnings: 30

Vulnerable environment confirmed — 20 critical findings detected.
These are expected — this is a deliberately misconfigured test environment.
```

Each finding maps to a specific misconfigured resource. See [`tests/README.md`](./tests/README.md) for the full mapping table.

---

## Quick Reference — Most Critical Controls

```bash
# Root account — should return 0
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'

# Users with no MFA
aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | cut -d',' -f1,4,8 | grep ',false'

# EC2 instances with IMDSv1 enabled (should be empty)
aws ec2 describe-instances \
  --filters "Name=metadata-options.http-tokens,Values=optional" \
  --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Security groups with SSH open to world
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
            "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table

# RDS instances that are publicly accessible
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine]' \
  --output table

# CloudTrail status
aws cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' \
  --output table
```

---

## Repo Structure

```
aws-security-best-practices/
├── README.md
├── LICENSE
├── DEPLOY.md                        ← GitHub Pages + Cloudflare DNS setup
├── index.html                       ← Interactive portfolio site (terminal aesthetic)
├── .github/workflows/
│   └── deploy.yml                   ← Auto-deploys index.html to GitHub Pages
├── docs/
│   ├── 01-iam-credentials/          ← 4 docs: static keys, role abuse, priv esc, SSO
│   ├── 02-ec2-compute/              ← 3 docs: IMDSv2, instance roles, SSH hardening
│   ├── 03-network-vpc/              ← 3 docs: security groups, VPC endpoints, flow logs
│   ├── 04-cicd-pipeline/            ← 3 docs: OIDC auth, secrets, pipeline hardening
│   ├── 05-s3/                       ← 3 docs: public access, bucket policies, data protection
│   ├── 06-lambda/                   ← 3 docs: execution roles, env vars, function hardening
│   ├── 07-rds/                      ← 3 docs: public access, auth/encryption, auditing
│   └── 08-detection/                ← 3 docs: CloudTrail, GuardDuty, Security Hub
├── scripts/
│   ├── audit-iam.sh
│   ├── audit-ec2.sh
│   ├── audit-network.sh
│   └── audit-s3-rds.sh
└── tests/
    ├── README.md                    ← Test harness docs + finding → resource mapping
    ├── requirements.txt             ← moto + boto3
    ├── test-all.sh                  ← One-command test runner
    ├── setup_vulnerable_env.py      ← Creates misconfigured resources in moto
    └── run-audit-local.sh           ← Runs all 4 scripts against moto
```

---

## License

This project is licensed under the [MIT License](./LICENSE) — free to use, share, and adapt with attribution.

---

## Contributing

Found a gap or a new attack vector? PRs welcome. Follow the existing format:

1. Explain the attack scenario first
2. Show the CLI commands to detect it in a live account
3. Show the CLI commands to fix it
4. Add a checklist at the end
5. If adding a new misconfigured resource for testing, update `tests/setup_vulnerable_env.py` and `tests/README.md`