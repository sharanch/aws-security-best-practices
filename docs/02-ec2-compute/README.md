# 02 — EC2 & Compute Security

EC2 instances are a common entry point for attackers — either directly (exposed SSH, vulnerable apps) or as a stepping stone to steal IAM role credentials via IMDS.

## Topics

| File | Topic |
|------|-------|
| [01-imdsv2.md](./01-imdsv2.md) | Enforcing IMDSv2 to block credential theft |
| [02-instance-roles.md](./02-instance-roles.md) | Scoping instance roles to least privilege |
| [03-ssh-hardening.md](./03-ssh-hardening.md) | Eliminating SSH keys in favor of SSM Session Manager |

## Key Threat Model

```
Exposed SSH (port 22)        Vulnerable App (SSRF)      Overprivileged Role
        │                            │                          │
        ▼                            ▼                          ▼
Shell access to instance     IMDS credential theft      Blast radius = full account
```

## Top 5 EC2 Controls

1. Enforce IMDSv2 on all instances — blocks SSRF-based credential theft
2. Remove SSH port 22 from security groups — use SSM Session Manager
3. Run instances in private subnets — no direct internet exposure
4. Scope instance IAM roles to the minimum needed
5. Enable VPC Flow Logs to detect unusual outbound traffic
