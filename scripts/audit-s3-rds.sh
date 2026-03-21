#!/usr/bin/env bash
# audit-s3-rds.sh — S3 and RDS security audit script
# Usage: ./audit-s3-rds.sh [--profile <aws-profile>] [--region <region>]

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

PROFILE=""
REGION="ap-south-1"

while [[ $# -gt 0 ]]; do
  case $1 in
    --profile) PROFILE="--profile $2"; shift 2 ;;
    --region)  REGION="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

AWS="aws $PROFILE --region $REGION"
CRITICAL_COUNT=0
WARNING_COUNT=0

critical() { echo -e "${RED}[CRITICAL]${RESET} $1"; ((CRITICAL_COUNT++)); }
warning()  { echo -e "${YELLOW}[WARNING] ${RESET} $1"; ((WARNING_COUNT++)); }
pass()     { echo -e "${GREEN}[PASS]    ${RESET} $1"; }
info()     { echo -e "${CYAN}[INFO]    ${RESET} $1"; }
header()   { echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"; \
             echo -e "${BOLD}  $1${RESET}"; \
             echo -e "${BOLD}══════════════════════════════════════════${RESET}"; }

# ─── S3: Account-Level Block Public Access ────────────────────────────────────
header "S3 — Account-Level Block Public Access"

ACCOUNT_ID=$($AWS sts get-caller-identity --query 'Account' --output text)

BPA=$($AWS s3control get-public-access-block --account-id $ACCOUNT_ID 2>/dev/null || echo "NONE")

if [[ "$BPA" == "NONE" ]]; then
  critical "S3 account-level Block Public Access is NOT configured"
else
  for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
    val=$(echo "$BPA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PublicAccessBlockConfiguration',{}).get('$setting','false'))" 2>/dev/null || echo "false")
    [[ "$val" == "True" ]] && pass "S3 account BPA: $setting = true" \
      || critical "S3 account BPA: $setting = false"
  done
fi

# ─── S3: Per-Bucket Checks ────────────────────────────────────────────────────
header "S3 — Per-Bucket Security"

BUCKETS=$($AWS s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null | tr '\t' '\n')
BUCKET_COUNT=$(echo "$BUCKETS" | grep -c . 2>/dev/null || echo "0")
info "Auditing $BUCKET_COUNT buckets..."

echo "$BUCKETS" | while read -r bucket; do
  [[ -z "$bucket" ]] && continue

  # Public policy check
  is_public=$($AWS s3api get-bucket-policy-status --bucket "$bucket" \
    --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "false")
  [[ "$is_public" == "true" ]] && critical "Bucket '$bucket' is PUBLIC via bucket policy"

  # Encryption check
  enc=$($AWS s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "NONE")
  [[ "$enc" == "NONE" ]] && warning "Bucket '$bucket' has no default encryption"

  # Versioning check
  versioning=$($AWS s3api get-bucket-versioning --bucket "$bucket" \
    --query 'Status' --output text 2>/dev/null || echo "Disabled")
  [[ "$versioning" != "Enabled" ]] && \
    warning "Bucket '$bucket' versioning is $versioning"

  # Logging check
  logging=$($AWS s3api get-bucket-logging --bucket "$bucket" \
    --query 'LoggingEnabled' --output text 2>/dev/null || echo "None")
  [[ "$logging" == "None" || -z "$logging" ]] && \
    warning "Bucket '$bucket' has no access logging enabled"

done

# ─── S3: Public Snapshots ─────────────────────────────────────────────────────
header "S3 — Dangerous Bucket Policies (Principal: *)"

$AWS s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null | \
  tr '\t' '\n' | while read -r bucket; do
  [[ -z "$bucket" ]] && continue
  policy=$($AWS s3api get-bucket-policy --bucket "$bucket" \
    --query 'Policy' --output text 2>/dev/null || echo "")
  if [[ -n "$policy" ]]; then
    has_star=$(echo "$policy" | python3 -c "
import sys, json
try:
    p = json.loads(sys.stdin.read())
    for stmt in p.get('Statement', []):
        principal = stmt.get('Principal', '')
        effect = stmt.get('Effect', '')
        if effect == 'Allow' and (principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*')):
            cond = stmt.get('Condition', {})
            if not cond:
                print('UNCONDITIONED')
                break
except: pass
" 2>/dev/null || echo "")
    [[ "$has_star" == "UNCONDITIONED" ]] && \
      critical "Bucket '$bucket' has Principal: * with no conditions — publicly accessible"
  fi
done

# ─── RDS: Public Access ───────────────────────────────────────────────────────
header "RDS — Public Accessibility"

PUBLIC_RDS=$($AWS rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$PUBLIC_RDS" ]]; then
  while IFS=$'\t' read -r db_id engine endpoint; do
    critical "RDS instance $db_id ($engine) is PUBLICLY ACCESSIBLE at $endpoint"
  done <<< "$PUBLIC_RDS"
else
  pass "No RDS instances are publicly accessible"
fi

# ─── RDS: Encryption ─────────────────────────────────────────────────────────
header "RDS — Encryption at Rest"

$AWS rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,KmsKeyId]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r db_id encrypted kms_key; do
  [[ -z "$db_id" ]] && continue
  if [[ "$encrypted" == "False" ]]; then
    critical "RDS instance $db_id is NOT encrypted at rest"
  else
    [[ -z "$kms_key" || "$kms_key" == "None" ]] && \
      warning "RDS instance $db_id uses default encryption — consider customer-managed KMS key" || \
      pass "RDS instance $db_id is encrypted with KMS key"
  fi
done

# ─── RDS: IAM Auth and Deletion Protection ────────────────────────────────────
header "RDS — IAM Auth and Deletion Protection"

$AWS rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,IAMDatabaseAuthenticationEnabled,DeletionProtection,BackupRetentionPeriod,MultiAZ]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r db_id iam_auth del_protect backup_days multi_az; do
  [[ -z "$db_id" ]] && continue

  [[ "$iam_auth" == "False" ]] && \
    warning "RDS $db_id IAM database authentication is disabled — static passwords in use"

  [[ "$del_protect" == "False" ]] && \
    warning "RDS $db_id deletion protection is DISABLED — can be deleted accidentally"

  [[ "$backup_days" == "0" ]] && \
    critical "RDS $db_id automated backups are DISABLED — no recovery possible"

  [[ "$multi_az" == "False" ]] && \
    warning "RDS $db_id is single-AZ — no HA protection"

  [[ "$iam_auth" == "True" && "$del_protect" == "True" && "$backup_days" != "0" ]] && \
    pass "RDS $db_id baseline config looks good (IAM auth, deletion protection, backups enabled)"
done

# ─── RDS: Public Snapshots ────────────────────────────────────────────────────
header "RDS — Public Snapshots"

$AWS rds describe-db-snapshots \
  --snapshot-type manual \
  --query 'DBSnapshots[*].DBSnapshotIdentifier' --output text 2>/dev/null | \
  tr '\t' '\n' | while read -r snapshot; do
  [[ -z "$snapshot" ]] && continue
  attrs=$($AWS rds describe-db-snapshot-attributes \
    --db-snapshot-identifier "$snapshot" \
    --query 'DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName==`restore`].AttributeValues[]' \
    --output text 2>/dev/null || echo "")
  if echo "$attrs" | grep -q "all"; then
    critical "RDS snapshot $snapshot is PUBLICLY SHARED — anyone can restore it"
  fi
done

# ─── Lambda: Env Var Secrets ──────────────────────────────────────────────────
header "Lambda — Suspicious Environment Variables"

$AWS lambda list-functions \
  --query 'Functions[*].FunctionName' --output text 2>/dev/null | tr '\t' '\n' | \
  while read -r fn; do
  [[ -z "$fn" ]] && continue
  env_vars=$($AWS lambda get-function-configuration \
    --function-name "$fn" \
    --query 'Environment.Variables' --output json 2>/dev/null || echo "{}")

  found=$(echo "$env_vars" | python3 -c "
import sys, json
risky = ['PASSWORD', 'SECRET', 'PRIVATE_KEY', 'API_KEY', 'TOKEN', 'CREDENTIAL', 'PASSWD']
try:
    d = json.loads(sys.stdin.read())
    found = [k for k in d.keys() if any(p in k.upper() for p in risky)]
    if found:
        print(','.join(found))
except: pass
" 2>/dev/null || echo "")

  [[ -n "$found" ]] && warning "Lambda '$fn' has suspicious env vars: $found — move to Secrets Manager"
done

# ─── Lambda: Public URLs ──────────────────────────────────────────────────────
header "Lambda — Public Function URLs"

$AWS lambda list-functions \
  --query 'Functions[*].FunctionName' --output text 2>/dev/null | tr '\t' '\n' | \
  while read -r fn; do
  [[ -z "$fn" ]] && continue
  url_config=$($AWS lambda get-function-url-config --function-name "$fn" 2>/dev/null || echo "")
  if echo "$url_config" | grep -q '"AuthType": "NONE"'; then
    critical "Lambda '$fn' has a public URL with AuthType NONE — unauthenticated invocation possible"
  fi
done

# ─── Summary ──────────────────────────────────────────────────────────────────
header "Audit Summary"
echo -e "  ${RED}Critical issues: $CRITICAL_COUNT${RESET}"
echo -e "  ${YELLOW}Warnings:        $WARNING_COUNT${RESET}"

if [[ $CRITICAL_COUNT -gt 0 ]]; then
  echo -e "\n${RED}${BOLD}Action required — $CRITICAL_COUNT critical issue(s) found.${RESET}"
  exit 1
else
  echo -e "\n${GREEN}${BOLD}No critical issues found.${RESET}"
  exit 0
fi
