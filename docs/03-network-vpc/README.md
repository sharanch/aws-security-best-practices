# 03 — Network & VPC Security

Network security controls limit what attackers can reach and what compromised resources can communicate with. Even if an attacker gains access to a resource, network controls can contain the blast radius.

## Topics

| File | Topic |
|------|-------|
| [01-security-groups.md](./01-security-groups.md) | Locking down inbound/outbound rules |
| [02-vpc-endpoints.md](./02-vpc-endpoints.md) | Keeping AWS service traffic off the public internet |
| [03-flow-logs.md](./03-flow-logs.md) | Enabling and analyzing VPC Flow Logs |

## Key Threat Model

```
Overly permissive SGs       No VPC Endpoints              No Flow Logs
        │                          │                             │
        ▼                          ▼                             ▼
Open ports = attack surface  Credentials work outside VPC  No visibility into
Lateral movement easy        Data exfil over public internet  who talked to what
```

## Top 5 Network Controls

1. Security groups should deny all inbound by default — allow only specific ports/sources
2. Use VPC endpoints for S3, DynamoDB, STS — never route through IGW
3. Put all compute in private subnets — only load balancers in public
4. Enable VPC Flow Logs to S3 or CloudWatch
5. Use NACLs as a secondary stateless layer for critical subnets
