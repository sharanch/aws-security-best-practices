# S3 Public Access — Discovery, Misconfigs, and Lockdown

## Attack Scenarios

### Scenario 1 — Automated Public Bucket Discovery
Attackers and security researchers continuously scan for public S3 buckets using tools and permutation attacks:

```bash
# Attackers enumerate buckets by guessing common names
# common patterns: company-name-backup, company-prod-data, company-logs, company-assets

# Check if a bucket is publicly listable
curl -s https://company-backup.s3.amazonaws.com/
# If it returns an XML listing — it's wide open

# Check if a specific object is readable without auth
curl -I https://company-backup.s3.amazonaws.com/database-dump-2024.sql
# HTTP 200 = publicly readable, HTTP 403 = protected
```

### Scenario 2 — ACL Misconfiguration (Legacy)
S3 ACLs predate bucket policies and are a common source of accidental public exposure:

```bash
# Bucket accidentally granted public read via ACL
aws s3api put-bucket-acl \
  --bucket company-data \
  --acl public-read
# Now ANYONE can list and read all objects in this bucket

# Object-level ACL accidentally set to public
aws s3api put-object-acl \
  --bucket company-data \
  --key sensitive-report.pdf \
  --acl public-read
# This specific file is now publicly accessible even if bucket is private
```

### Scenario 3 — Static Website Hosting Left On
```bash
# Dev enabled static website hosting for testing, forgot to disable it
aws s3 website s3://company-internal-docs/ \
  --index-document index.html
# URL: http://company-internal-docs.s3-website-ap-south-1.amazonaws.com
# Block Public Access does NOT cover website endpoints — separate control needed
```

---

## Detection — Find Public Buckets

```bash
# 1. Check account-level Block Public Access (should all be true)
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
aws s3control get-public-access-block --account-id $ACCOUNT_ID

# 2. Check every bucket's individual block public access settings
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    result=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "NO_BLOCK")
    if [[ "$result" == "NO_BLOCK" ]]; then
      echo "WARNING: $bucket has no public access block configured"
    fi
  done

# 3. Find buckets with public ACLs
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    acl=$(aws s3api get-bucket-acl --bucket "$bucket" \
      --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`].Permission' \
      --output text 2>/dev/null || echo "")
    [[ -n "$acl" ]] && echo "CRITICAL: $bucket has public ACL: $acl"
  done

# 4. Find publicly accessible buckets via policy
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    status=$(aws s3api get-bucket-policy-status --bucket "$bucket" \
      --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "false")
    [[ "$status" == "true" ]] && echo "CRITICAL: $bucket is PUBLIC via bucket policy"
  done

# 5. Check for static website hosting enabled
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    website=$(aws s3api get-bucket-website --bucket "$bucket" 2>/dev/null && echo "ENABLED" || echo "")
    [[ "$website" == "ENABLED" ]] && echo "INFO: $bucket has static website hosting enabled"
  done

# 6. AWS Config rule — flag any public bucket immediately
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"}
  }'

aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-write-prohibited",
    "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"}
  }'
```

---

## Fix — Enable Block Public Access

```bash
# Fix 1: Enable at the ACCOUNT level (protects all current and future buckets)
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
aws s3control put-public-access-block \
  --account-id $ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,\
    IgnorePublicAcls=true,\
    BlockPublicPolicy=true,\
    RestrictPublicBuckets=true

# Fix 2: Enable per bucket (if account-level isn't set yet)
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text | tr '\t' '\n'); do
  echo "Blocking public access on: $bucket"
  aws s3api put-public-access-block \
    --bucket "$bucket" \
    --public-access-block-configuration \
      BlockPublicAcls=true,\
      IgnorePublicAcls=true,\
      BlockPublicPolicy=true,\
      RestrictPublicBuckets=true
done

# Fix 3: Disable object ACLs entirely (use bucket policies instead)
aws s3api put-bucket-ownership-controls \
  --bucket my-bucket \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
# This disables ACLs entirely — bucket policy is the only access control

# Fix 4: Disable static website hosting if not needed
aws s3api delete-bucket-website --bucket company-internal-docs
```

---

## Checklist

- [ ] Account-level S3 Block Public Access fully enabled (all 4 settings)
- [ ] Per-bucket Block Public Access enabled on all non-CDN buckets
- [ ] Object ownership set to `BucketOwnerEnforced` — ACLs disabled
- [ ] Static website hosting disabled on non-public buckets
- [ ] AWS Config rules `S3_BUCKET_PUBLIC_READ_PROHIBITED` and `WRITE_PROHIBITED` active
- [ ] CloudTrail S3 data events enabled for sensitive buckets
- [ ] GuardDuty S3 protection enabled — detects anomalous access patterns
