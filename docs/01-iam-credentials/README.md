# 01 — IAM & Credentials

IAM is the front door to your entire AWS account. Misconfigured IAM is the root cause of the majority of AWS breaches.

## Topics

| File | Topic |
|------|-------|
| [01-static-keys.md](./01-static-keys.md) | Risks of static access keys and how to eliminate them |
| [02-role-abuse.md](./02-role-abuse.md) | How IAM roles get abused and how to lock them down |
| [03-privilege-escalation.md](./03-privilege-escalation.md) | IAM privilege escalation paths and how to detect them |
| [04-identity-center.md](./04-identity-center.md) | Setting up IAM Identity Center (SSO) for human users |

## Key Threat Model

```
Static Keys Leaked          Role Misconfigured         Weak Trust Policy
       │                           │                          │
       ▼                           ▼                          ▼
Attacker has permanent      Attacker assumes role      Cross-account takeover
access to your account      from compromised EC2       from any AWS account
```

## Top 5 IAM Controls (Do These First)

1. Delete all root account access keys
2. Enable MFA on all IAM users, especially admin group
3. Replace static access keys with IAM Identity Center (SSO)
4. Apply SCPs to prevent disabling CloudTrail and GuardDuty
5. Run IAM Access Analyzer to find overly permissive policies
