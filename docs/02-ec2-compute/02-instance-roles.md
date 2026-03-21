# EC2 Instance Roles — Least Privilege

## The Problem

An EC2 instance role with overly broad permissions means any compromised process on the machine — malware, a vulnerable app, an attacker with shell — inherits those permissions automatically.

---

## Common Mistakes

```bash
# Mistake 1: Attaching AdministratorAccess to an instance
aws iam attach-role-policy \
  --role-name MyEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# Any code running on this EC2 = full AWS admin

# Mistake 2: Wildcard S3 access when only one bucket is needed
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
# Should be: specific bucket, specific actions only
```

---

## Detection — Audit Instance Role Permissions

```bash
# 1. Find the role attached to an EC2 instance
aws ec2 describe-instances \
  --instance-ids i-0123456789abcdef0 \
  --query 'Reservations[*].Instances[*].IamInstanceProfile.Arn' \
  --output text

# 2. Get the role name from instance profile
aws iam get-instance-profile \
  --instance-profile-name MyInstanceProfile \
  --query 'InstanceProfile.Roles[*].RoleName' \
  --output text

# 3. List all policies attached to the role
aws iam list-attached-role-policies --role-name MyEC2Role
aws iam list-role-policies --role-name MyEC2Role  # inline policies

# 4. Check for overly permissive policies
aws iam get-role-policy \
  --role-name MyEC2Role \
  --policy-name MyInlinePolicy

# 5. Find all EC2 roles with AdministratorAccess
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --entity-filter Role
```

---

## Fix — Apply Least Privilege

```bash
# Remove overly broad policy
aws iam detach-role-policy \
  --role-name MyEC2Role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

# Create a scoped-down policy — only what the app actually needs
aws iam create-policy \
  --policy-name AppMinimalS3Access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::my-specific-app-bucket/*"
      },
      {
        "Effect": "Allow",
        "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::my-specific-app-bucket"
      }
    ]
  }'

# Attach the scoped policy
aws iam attach-role-policy \
  --role-name MyEC2Role \
  --policy-arn arn:aws:iam::123456789:policy/AppMinimalS3Access
```

---

## Add Conditions to Limit Blast Radius

```bash
# Restrict S3 access to only your VPC endpoint
aws iam create-policy \
  --policy-name VpcScopedS3Access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::my-bucket/*"
      },
      {
        "Effect": "Deny",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {
          "StringNotEquals": {
            "aws:SourceVpce": "vpce-0123456789abcdef0"
          }
        }
      }
    ]
  }'
# Even if credentials are stolen, they only work inside your VPC
```

---

## Use IAM Access Advisor to Right-Size Permissions

```bash
# Generate a service last-accessed report for the role
aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::123456789:role/MyEC2Role

# Get the job ID from the response, then fetch results
aws iam get-service-last-accessed-details \
  --job-id <job-id> \
  --query 'ServicesLastAccessed[?TotalAuthenticatedEntities>`0`].[ServiceName,LastAuthenticated]' \
  --output table

# Services with LastAuthenticated = null or very old = remove them from the policy
```

---

## Checklist

- [ ] No EC2 instance has `AdministratorAccess` attached
- [ ] Instance roles scoped to specific resources (not `*`)
- [ ] IAM Access Advisor reviewed — unused services removed
- [ ] Permission boundaries applied to all instance roles
- [ ] VPC endpoint conditions on S3/DynamoDB access where possible
- [ ] Roles audited quarterly for permission creep
