# S3 Data Protection — Encryption, Versioning, and Ransomware Defense

## Attack Scenarios

### Scenario 1 — Ransomware via S3 Delete
```bash
# Attacker gains a role with s3:DeleteObject — deletes everything
aws s3 rm s3://company-critical-data --recursive
# Without versioning: data is gone permanently
# With versioning: objects are soft-deleted, recoverable

# More sophisticated: attacker overwrites files with encrypted garbage
aws s3 sync ./encrypted-junk/ s3://company-critical-data/ --delete
# Files look intact but are unreadable
```

### Scenario 2 — Unencrypted Data at Rest
```bash
# Attacker gains access to an EBS snapshot or S3 bucket
# If SSE is not enforced, data is stored in plaintext
# AWS employees, subpoenas, or physical media recovery = readable data

# Check if a bucket enforces encryption
aws s3api get-bucket-encryption --bucket my-bucket
# If this returns "ServerSideEncryptionConfigurationNotFoundError" — data is NOT encrypted by default
```

### Scenario 3 — Snapshot Made Public (RDS / EBS cross-reference)
```bash
# Attacker who compromised an admin role makes your S3 bucket snapshot public
# Or worse — copies your bucket to their account without encryption:
aws s3 sync s3://victim-bucket s3://attacker-bucket \
  --sse AES256  # Attacker re-encrypts with their own key — now they own it
```

### Scenario 4 — MFA Delete Bypassed
```bash
# Without MFA delete, anyone with the role can permanently delete versions
aws s3api delete-object \
  --bucket my-versioned-bucket \
  --key sensitive-file.pdf \
  --version-id abc123
# Version permanently gone — no MFA required unless MFA delete is enabled
```

---

## Detection

```bash
# 1. Find buckets without default encryption
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    enc=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "NONE")
    [[ "$enc" == "NONE" ]] && echo "WARNING: $bucket has no default encryption"
  done

# 2. Find buckets without versioning enabled
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  tr '\t' '\n' | while read -r bucket; do
    versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" \
      --query 'Status' --output text 2>/dev/null || echo "Disabled")
    [[ "$versioning" != "Enabled" ]] && \
      echo "WARNING: $bucket has versioning $versioning"
  done

# 3. Detect mass delete events (ransomware indicator)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'Events[*].[EventTime,Username,Resources[0].ResourceName]' \
  --output table

# Count deletes in last hour — alarm if unusually high
DELETE_COUNT=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --query 'length(Events)' --output text)
echo "DeleteObject events in last hour: $DELETE_COUNT"

# 4. Check if MFA delete is enabled on critical buckets
aws s3api get-bucket-versioning --bucket my-critical-bucket
# Look for: "MFADelete": "Enabled"

# 5. AWS Config rules for encryption
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    }
  }'
```

---

## Fix — Encryption, Versioning, and Object Lock

```bash
# Fix 1: Enable default encryption with KMS
aws s3api put-bucket-encryption \
  --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:ap-south-1:123456789:key/key-id"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Fix 2: Enforce encryption — deny unencrypted uploads
cat <<'EOF'
# Add to bucket policy:
{
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::my-bucket/*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
EOF

# Fix 3: Enable versioning
aws s3api put-bucket-versioning \
  --bucket my-critical-bucket \
  --versioning-configuration Status=Enabled

# Fix 4: Enable MFA Delete (requires root credentials)
aws s3api put-bucket-versioning \
  --bucket my-critical-bucket \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::123456789:mfa/root-account-mfa-device 123456"

# Fix 5: Enable S3 Object Lock (WORM — Write Once Read Many)
# Must be enabled at bucket creation
aws s3api create-bucket \
  --bucket my-compliance-bucket \
  --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1 \
  --object-lock-enabled-for-bucket

# Set default retention — no one can delete for 90 days
aws s3api put-object-lock-configuration \
  --bucket my-compliance-bucket \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Days": 90
      }
    }
  }'

# Fix 6: Lifecycle policy to expire old versions (cost + security hygiene)
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-critical-bucket \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "expire-old-versions",
      "Status": "Enabled",
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 30
      },
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 7
      }
    }]
  }'
```

---

## Recover from Ransomware / Mass Delete

```bash
# List all deleted versions of a file
aws s3api list-object-versions \
  --bucket my-versioned-bucket \
  --prefix sensitive-file.pdf \
  --query 'DeleteMarkers[*].[VersionId,LastModified]' \
  --output table

# Remove the delete marker to restore the file
aws s3api delete-object \
  --bucket my-versioned-bucket \
  --key sensitive-file.pdf \
  --version-id <delete-marker-version-id>
# File is restored to its previous state

# Restore all files deleted in a ransomware attack
aws s3api list-object-versions \
  --bucket my-versioned-bucket \
  --query 'DeleteMarkers[*].[Key,VersionId]' \
  --output text | while read -r key version_id; do
    echo "Restoring: $key"
    aws s3api delete-object \
      --bucket my-versioned-bucket \
      --key "$key" \
      --version-id "$version_id"
  done
```

---

## Checklist

- [ ] Default encryption enabled on all buckets (aws:kms preferred)
- [ ] Bucket policy denies unencrypted `PutObject` requests
- [ ] Versioning enabled on all buckets containing important data
- [ ] MFA delete enabled on critical/compliance buckets
- [ ] S3 Object Lock (WORM) on compliance/audit log buckets
- [ ] Lifecycle policy to expire old versions after 30 days
- [ ] CloudWatch alarm on high `DeleteObject` volume (ransomware detection)
- [ ] AWS Config rule `S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED` active
