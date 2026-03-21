# 04 — CI/CD Pipeline Security

CI/CD pipelines are high-value targets — they have AWS credentials, access to source code, and the ability to deploy to production. A compromised pipeline = a compromised production environment.

## Topics

| File | Topic |
|------|-------|
| [01-oidc-auth.md](./01-oidc-auth.md) | Replacing static keys with OIDC federation |
| [02-secrets-management.md](./02-secrets-management.md) | Managing secrets in pipelines securely |
| [03-pipeline-hardening.md](./03-pipeline-hardening.md) | General pipeline hardening practices |

## Key Threat Model

```
Static AWS Keys in CI        Secrets in Plaintext         Supply Chain Attack
        │                           │                             │
        ▼                           ▼                             ▼
Key leaked in logs or       Secrets visible in build     Malicious dependency
repo = permanent access     logs or env dump             reads env vars + exfils
```

## Top 5 CI/CD Controls

1. Use OIDC for GitHub Actions / GitLab CI — eliminate static AWS keys entirely
2. Never print environment variables in CI logs
3. Store secrets in AWS Secrets Manager — not CI/CD platform variables
4. Scope deployment roles to least privilege per environment
5. Pin third-party actions to a commit SHA — not a mutable tag
