# VPC Endpoints — Keep AWS Traffic Off the Public Internet

## The Problem

Without VPC endpoints, traffic to AWS services (S3, DynamoDB, STS, etc.) leaves your VPC, travels over the public internet, and returns. This means stolen credentials work from anywhere, and sensitive data is routed unnecessarily over public networks.

---

## Types of VPC Endpoints

```
Gateway Endpoints          Interface Endpoints
─────────────────          ───────────────────
Free                       Hourly + data cost
S3 and DynamoDB only       Most other AWS services
Route table entry          ENI in your subnet
                           Supports PrivateLink
```

---

## The Key Security Benefit

```bash
# Without VPC endpoint:
# EC2 → Internet Gateway → Public AWS S3 endpoint
# Stolen credentials usable from ANYWHERE on the internet

# With VPC endpoint + bucket policy:
# EC2 → VPC Endpoint → S3 (stays in AWS network)
# Stolen credentials ONLY work from inside your VPC
```

---

## Detection — Check for Missing VPC Endpoints

```bash
# List existing VPC endpoints in your VPC
aws ec2 describe-vpc-endpoints \
  --filters "Name=vpc-id,Values=vpc-0123456789abcdef0" \
  --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State]' \
  --output table

# Check if S3 gateway endpoint exists
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.ap-south-1.s3" \
             "Name=vpc-id,Values=vpc-0123456789abcdef0" \
  --query 'VpcEndpoints[*].[VpcEndpointId,State,VpcEndpointType]'

# Find all available AWS endpoint services in your region
aws ec2 describe-vpc-endpoint-services \
  --query 'ServiceNames' --output text | tr '\t' '\n' | sort
```

---

## Fix — Create VPC Endpoints

### Gateway Endpoint for S3 (Free)
```bash
# Get your route table IDs for private subnets
aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=vpc-0123456789abcdef0" \
  --query 'RouteTables[*].[RouteTableId,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Create S3 gateway endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0123456789abcdef0 \
  --service-name com.amazonaws.ap-south-1.s3 \
  --route-table-ids rtb-0123456789abcdef0 rtb-abcdef0123456789  # all private route tables
  --vpc-endpoint-type Gateway

# Create DynamoDB gateway endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0123456789abcdef0 \
  --service-name com.amazonaws.ap-south-1.dynamodb \
  --route-table-ids rtb-0123456789abcdef0 \
  --vpc-endpoint-type Gateway
```

### Interface Endpoint for STS (Prevents Credential Use Outside VPC)
```bash
# Create STS interface endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0123456789abcdef0 \
  --service-name com.amazonaws.ap-south-1.sts \
  --vpc-endpoint-type Interface \
  --subnet-ids subnet-private-1 subnet-private-2 \
  --security-group-ids sg-vpce-sg \
  --private-dns-enabled  # Overrides public DNS — all STS calls go through endpoint
```

---

## Lock Down S3 Bucket — Deny Access Outside VPC

```bash
# Add a bucket policy that blocks all access not coming through your VPC endpoint
aws s3api put-bucket-policy \
  --bucket my-sensitive-bucket \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::my-sensitive-bucket",
          "arn:aws:s3:::my-sensitive-bucket/*"
        ]
      },
      {
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::my-sensitive-bucket",
          "arn:aws:s3:::my-sensitive-bucket/*"
        ],
        "Condition": {
          "StringNotEquals": {
            "aws:SourceVpce": "vpce-0123456789abcdef0"
          }
        }
      }
    ]
  }'

# Test — should work from inside VPC
aws s3 ls s3://my-sensitive-bucket

# Test — should fail from outside VPC (e.g., your laptop with stolen creds)
AWS_ACCESS_KEY_ID=stolen-key aws s3 ls s3://my-sensitive-bucket
# Access Denied — even with valid credentials
```

---

## Recommended Endpoints to Create

| Service | Type | Why |
|---|---|---|
| S3 | Gateway (free) | Most apps use S3 — keep traffic off internet |
| DynamoDB | Gateway (free) | Same — high traffic service |
| STS | Interface | Prevent stolen tokens from working outside VPC |
| SSM | Interface | Required for Session Manager without internet |
| EC2 | Interface | Instance metadata and API calls |
| Secrets Manager | Interface | Secret fetching stays private |
| CloudWatch Logs | Interface | Log shipping stays in VPC |

---

## Checklist

- [ ] S3 gateway endpoint exists for all VPCs with S3-accessing workloads
- [ ] DynamoDB gateway endpoint created
- [ ] STS interface endpoint created — credential usage restricted to VPC
- [ ] S3 bucket policies deny access outside VPC endpoint
- [ ] SSM interface endpoints created — enables Session Manager in private subnets
- [ ] VPC endpoint policies scoped (not open to all principals/actions)
