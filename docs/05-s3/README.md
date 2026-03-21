# 05 — S3 Security

S3 misconfigurations are responsible for some of the largest data breaches in history — Capital One, GoDaddy, and dozens of others. The combination of "easy to make public" and "stores everything" makes S3 a high-value target.

## Topics

| File | Topic |
|------|-------|
| [01-public-access.md](./01-public-access.md) | Public bucket discovery, ACL vs policy confusion, block public access |
| [02-bucket-policies.md](./02-bucket-policies.md) | Dangerous policy patterns, cross-account exfiltration, least privilege |
| [03-data-protection.md](./03-data-protection.md) | Encryption, versioning, ransomware protection, presigned URL abuse |

## Key Threat Model

```
Public Bucket               Overpermissive Policy         No Versioning
      │                             │                           │
      ▼                             ▼                           ▼
Anyone reads/writes         Stolen role exfiltrates     Ransomware deletes
your data                   to attacker's account       everything, no recovery
```

## Top 5 S3 Controls

1. Enable S3 Block Public Access at the account level — one setting protects all buckets
2. Never use `Principal: *` in bucket policies without strict conditions
3. Enable versioning + MFA delete on critical buckets
4. Scope IAM roles to specific bucket ARNs — never `arn:aws:s3:::*`
5. Enable S3 server access logging and CloudTrail data events
