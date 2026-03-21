# 06 — Lambda Security

Lambda functions are often overlooked in security reviews — they're "serverless" so they feel invisible. But every Lambda has an execution role, network access, environment variables, and a public or private invocation surface.

## Topics

| File | Topic |
|------|-------|
| [01-execution-roles.md](./01-execution-roles.md) | Overprivileged execution roles and least privilege scoping |
| [02-env-vars-secrets.md](./02-env-vars-secrets.md) | Secrets in environment variables — risks and remediation |
| [03-function-hardening.md](./03-function-hardening.md) | Lambda URLs, resource policies, VPC attachment, supply chain |

## Key Threat Model

```
Overprivileged Role          Secrets in Env Vars          Public Lambda URL
       │                             │                           │
       ▼                             ▼                           ▼
Compromised function         Any code path can read        Anyone can invoke
= full account access        and exfiltrate secrets        your function
```

## Top 5 Lambda Controls

1. Execution roles scoped to exactly what the function needs — nothing more
2. Secrets fetched from Secrets Manager at runtime — never stored in env vars
3. Lambda URLs disabled unless explicitly needed, with auth type `AWS_IAM`
4. Functions deployed inside a VPC for anything touching databases or internal services
5. Dependencies pinned and scanned — supply chain attacks target Lambda packages
