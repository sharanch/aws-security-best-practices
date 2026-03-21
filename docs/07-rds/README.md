# 07 — RDS & Database Security

Databases are the crown jewels. A publicly exposed or poorly secured RDS instance gives attackers direct access to your most sensitive data — without going through your application layer at all.

## Topics

| File | Topic |
|------|-------|
| [01-public-access.md](./01-public-access.md) | Publicly accessible RDS, security group exposure, subnet placement |
| [02-auth-encryption.md](./02-auth-encryption.md) | IAM database auth, static credentials, encryption at rest and in transit |
| [03-auditing-backups.md](./03-auditing-backups.md) | Audit logging, snapshot security, deletion protection |

## Key Threat Model

```
Public RDS Instance          Static Master Password        Unencrypted Snapshot
        │                            │                              │
        ▼                            ▼                              ▼
Internet can attempt        Leaked once = permanent        Snapshot shared or copied
brute force directly        DB access                      = all data in plaintext
```

## Top 5 RDS Controls

1. `PubliclyAccessible: false` on every RDS instance — databases live in private subnets only
2. Enable IAM database authentication — short-lived tokens instead of static passwords
3. Rotate master credentials via Secrets Manager automatic rotation
4. Enable encryption at rest using KMS — applies to storage, snapshots, and replicas
5. Enable deletion protection and automated backups — ransomware and accidental deletes
