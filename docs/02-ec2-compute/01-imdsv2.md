# IMDSv2 — Instance Metadata Service Hardening

## The Problem

The Instance Metadata Service (IMDS) at `169.254.169.254` exposes IAM role credentials to any process on the EC2 instance. IMDSv1 requires only a simple GET request — trivially exploitable via SSRF vulnerabilities or direct shell access.

---

## IMDSv1 vs IMDSv2

```
IMDSv1 (insecure)                   IMDSv2 (secure)
─────────────────                   ───────────────
Single GET request                  Two-step: PUT token first, then GET
No session required                 Session token required (TTL: 1-21600s)
Exploitable via SSRF                SSRF can't do the PUT step
curl http://169.254.169.254/...     Requires custom header X-aws-ec2-metadata-token
```

---

## Attack — IMDSv1 Credential Theft via SSRF

```bash
# Vulnerable app at: https://myapp.com/fetch?url=<target>
# Attacker sends:
curl "https://myapp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: MyAppRole

curl "https://myapp.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyAppRole"
# Response: {"AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..."}
# Attacker now has credentials valid for 1 hour
```

With IMDSv2, the PUT step uses a custom header that SSRF proxies typically cannot forward:
```bash
# IMDSv2 requires this first step — SSRF usually can't replicate it
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Then use the token
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

---

## Detection — Find Instances Without IMDSv2

```bash
# Check all instances — find those still on IMDSv1 (HttpTokens = optional)
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Filter only the non-compliant ones
aws ec2 describe-instances \
  --filters "Name=metadata-options.http-tokens,Values=optional" \
  --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress]' \
  --output table

# Count of non-compliant instances
aws ec2 describe-instances \
  --filters "Name=metadata-options.http-tokens,Values=optional" \
  --query 'length(Reservations[*].Instances[*])' \
  --output text
```

---

## Fix — Enforce IMDSv2

```bash
# Enforce on a single instance (no restart required)
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1

# Enforce on ALL instances in a region (use carefully)
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].InstanceId' \
  --output text | tr '\t' '\n' | while read instance_id; do
    echo "Enforcing IMDSv2 on $instance_id"
    aws ec2 modify-instance-metadata-options \
      --instance-id "$instance_id" \
      --http-tokens required \
      --http-endpoint enabled
  done

# Verify enforcement
aws ec2 describe-instances \
  --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[*].Instances[*].MetadataOptions'
# Should show: "HttpTokens": "required"
```

---

## Prevention — Enforce at Launch via AWS Config

```bash
# Create an AWS Config rule to flag non-IMDSv2 instances
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "ec2-imdsv2-required",
    "Description": "Checks that all EC2 instances require IMDSv2",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "EC2_IMDSV2_REQUIRED"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::EC2::Instance"]
    }
  }'

# Check compliance status
aws configservice describe-compliance-by-config-rule \
  --config-rule-names ec2-imdsv2-required

# Set hop limit to 1 — prevents containers on the instance from reaching IMDS
# (hop limit of 2 needed only if using containers on EC2)
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-put-response-hop-limit 1 \
  --http-tokens required
```

---

## Prevention — Block IMDSv1 in Launch Templates

```bash
# Create a launch template that enforces IMDSv2 by default
aws ec2 create-launch-template \
  --launch-template-name secure-default \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpEndpoint": "enabled",
      "HttpPutResponseHopLimit": 1
    }
  }'

# Use this template for all new instances
aws ec2 run-instances \
  --launch-template LaunchTemplateName=secure-default \
  --image-id ami-12345678 \
  --instance-type t3.micro
```

---

## Checklist

- [ ] All existing instances set to `HttpTokens: required`
- [ ] Launch templates enforce IMDSv2 by default
- [ ] AWS Config rule `EC2_IMDSV2_REQUIRED` active and monitored
- [ ] Hop limit set to 1 (or 2 if running containers on EC2)
- [ ] CloudWatch alarm on IMDSv1 usage metrics
- [ ] Application code updated to use IMDSv2 token if directly calling IMDS
