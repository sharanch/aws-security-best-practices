# 08 — Detection & Response (CloudTrail, GuardDuty, Security Hub)

Prevention controls will eventually fail. When they do, detection speed determines the blast radius. The difference between a minor incident and a catastrophic breach is often how quickly you find out.

## Topics

| File | Topic |
|------|-------|
| [01-cloudtrail.md](./01-cloudtrail.md) | Hardening CloudTrail, log protection, forensic queries |
| [02-guardduty.md](./02-guardduty.md) | GuardDuty threat findings, alerting, and response automation |
| [03-security-hub.md](./03-security-hub.md) | Security Hub aggregation, standards, and SIEM integration |

## Key Threat Model

```
CloudTrail Disabled          GuardDuty Finding Ignored      No Aggregation
       │                              │                           │
       ▼                              ▼                           ▼
Attacker covers tracks        Breach ongoing for weeks      Siloed findings —
No forensic evidence          before anyone notices         no full picture
```

## The Detection Stack

```
Individual Services (EC2, S3, RDS, Lambda)
              │ emit events
              ▼
        CloudTrail          ← API-level audit log (who did what, when, from where)
        VPC Flow Logs       ← Network-level visibility (who talked to who)
        CloudWatch Logs     ← Application and service logs
              │ feeds into
              ▼
         GuardDuty          ← Threat intelligence, ML anomaly detection
         AWS Config         ← Configuration drift and compliance
              │ aggregated by
              ▼
        Security Hub        ← Single pane of glass, findings normalized
              │ triggers
              ▼
    EventBridge + SNS/Lambda ← Automated response and alerting
```

## Top 5 Detection Controls

1. CloudTrail enabled in all regions with log file validation and locked S3 bucket
2. GuardDuty enabled in all regions — never disable it, even in dev
3. Security Hub enabled with CIS AWS Foundations and AWS Foundational Security standards
4. CloudWatch metric filters and alarms on root login, IAM changes, and CloudTrail stoppage
5. Automated response via EventBridge — don't rely on humans checking consoles
