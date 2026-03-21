#!/usr/bin/env bash
# audit-iam.sh — IAM security audit script
# Usage: ./audit-iam.sh [--profile <aws-profile>] [--region <region>]
# Output: Prints findings to stdout, exits 1 if critical issues found

set -uo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Argument Parsing ─────────────────────────────────────────────────────────
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

# ─── Helpers ──────────────────────────────────────────────────────────────────
critical() { echo -e "${RED}[CRITICAL]${RESET} $1"; ((CRITICAL_COUNT++)); }
warning()  { echo -e "${YELLOW}[WARNING] ${RESET} $1"; ((WARNING_COUNT++)); }
pass()     { echo -e "${GREEN}[PASS]    ${RESET} $1"; }
info()     { echo -e "${CYAN}[INFO]    ${RESET} $1"; }
header()   { echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"; \
             echo -e "${BOLD}  $1${RESET}"; \
             echo -e "${BOLD}══════════════════════════════════════════${RESET}"; }

# ─── 1. Root Account Checks ───────────────────────────────────────────────────
header "1. Root Account"

ROOT_KEYS=$($AWS iam get-account-summary \
  --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null || echo "0")

if [[ "$ROOT_KEYS" -gt 0 ]]; then
  critical "Root account has active access keys — delete them immediately"
else
  pass "Root account has no active access keys"
fi

ROOT_MFA=$($AWS iam get-account-summary \
  --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null || echo "0")

if [[ "$ROOT_MFA" -eq 0 ]]; then
  critical "Root account does not have MFA enabled"
else
  pass "Root account MFA is enabled"
fi

# ─── 2. IAM Users ─────────────────────────────────────────────────────────────
header "2. IAM Users — Credentials"

# Generate credential report
info "Generating credential report..."
$AWS iam generate-credential-report > /dev/null 2>&1 || true
sleep 5

REPORT=$($AWS iam get-credential-report \
  --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")

# Users with no MFA
echo "$REPORT" | tail -n +2 | while IFS=',' read -r user arn user_creation_time \
  password_enabled password_last_used password_last_changed \
  password_next_rotation mfa_active \
  access_key_1_active access_key_1_last_rotated access_key_1_last_used_date \
  access_key_1_last_used_region access_key_1_last_used_service \
  access_key_2_active access_key_2_last_rotated access_key_2_last_used_date \
  access_key_2_last_used_region access_key_2_last_used_service \
  cert_1_active cert_2_active; do

  [[ "$user" == "user" ]] && continue  # Skip header

  # Check MFA
  if [[ "$mfa_active" == "false" && "$password_enabled" == "true" ]]; then
    warning "User '$user' has console access but NO MFA enabled"
  fi

  # Check key 1 age
  if [[ "$access_key_1_active" == "true" ]]; then
    key_age=$(( ( $(date +%s) - $(date -d "$access_key_1_last_rotated" +%s 2>/dev/null || echo 0) ) / 86400 ))
    if [[ $key_age -gt 90 ]]; then
      warning "User '$user' access key 1 is ${key_age} days old (rotate if >90 days)"
    fi
    # Check for keys never used
    if [[ "$access_key_1_last_used_date" == "N/A" ]]; then
      warning "User '$user' access key 1 has never been used — consider deleting"
    fi
  fi

  # Check key 2 age
  if [[ "$access_key_2_active" == "true" ]]; then
    key_age=$(( ( $(date +%s) - $(date -d "$access_key_2_last_rotated" +%s 2>/dev/null || echo 0) ) / 86400 ))
    if [[ $key_age -gt 90 ]]; then
      warning "User '$user' access key 2 is ${key_age} days old"
    fi
  fi

done || true

# ─── 3. Admin Access ──────────────────────────────────────────────────────────
header "3. Admin Access — Who Has It"

info "Users with AdministratorAccess policy:"
# Try AWS partition ARN first (real AWS), fall back to account-scoped ARN (moto)
ADMIN_POLICY_ARN="arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_POLICY_ARN_ACCOUNT="arn:aws:iam::$(${AWS} sts get-caller-identity --query Account --output text 2>/dev/null || echo '123456789012'):policy/AdministratorAccess"

ALL_USERS=""
for arn in "$ADMIN_POLICY_ARN" "$ADMIN_POLICY_ARN_ACCOUNT"; do
  U=$($AWS iam list-entities-for-policy \
    --policy-arn "$arn" \
    --entity-filter User \
    --query 'PolicyUsers[*].UserName' --output text 2>/dev/null || echo "")
  ALL_USERS="$ALL_USERS $U"
done
echo "$ALL_USERS" | tr ' \t' '\n' | sort -u | while read -r user; do
  [[ -z "$user" ]] && continue
  [[ "$user" =~ ^[0-9]+$ ]] && continue
  warning "User '$user' has AdministratorAccess attached directly"
done

info "Roles with AdministratorAccess policy:"
ALL_ROLES=""
for arn in "$ADMIN_POLICY_ARN" "$ADMIN_POLICY_ARN_ACCOUNT"; do
  R=$($AWS iam list-entities-for-policy \
    --policy-arn "$arn" \
    --entity-filter Role \
    --query 'PolicyRoles[*].RoleName' --output text 2>/dev/null || echo "")
  ALL_ROLES="$ALL_ROLES $R"
done
echo "$ALL_ROLES" | tr ' \t' '\n' | sort -u | while read -r role; do
  [[ -z "$role" ]] && continue
  [[ "$role" =~ ^[0-9]+$ ]] && continue
  warning "Role '$role' has AdministratorAccess attached — verify this is intentional"
done

info "Groups with AdministratorAccess policy:"
ALL_GROUPS=""
for arn in "$ADMIN_POLICY_ARN" "$ADMIN_POLICY_ARN_ACCOUNT"; do
  G=$($AWS iam list-entities-for-policy \
    --policy-arn "$arn" \
    --entity-filter Group \
    --query 'PolicyGroups[*].GroupName' --output text 2>/dev/null || echo "")
  ALL_GROUPS="$ALL_GROUPS $G"
done
echo "$ALL_GROUPS" | tr ' \t' '\n' | sort -u | while read -r group; do
  [[ -z "$group" ]] && continue
  # Skip numeric-only values (moto sometimes returns GIDs)
  [[ "$group" =~ ^[0-9]+$ ]] && continue
  info "Group '$group' has AdministratorAccess — check group membership"
done

# ─── 4. Dangerous Role Trust Policies ────────────────────────────────────────
header "4. Role Trust Policies — Overly Permissive"

ROLES_LIST=$($AWS iam list-roles \
  --query 'Roles[*].RoleName' --output text 2>/dev/null || echo "")

echo "$ROLES_LIST" | tr '\t' '\n' | while read -r role; do
  [[ -z "$role" ]] && continue
  trust=$($AWS iam get-role --role-name "$role" \
    --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null || echo "{}")

  if echo "$trust" | grep -q '"AWS": "\*"' 2>/dev/null; then
    critical "Role '$role' has Principal: * in trust policy — any AWS account can assume it"
  fi
done

# ─── 5. Password Policy ───────────────────────────────────────────────────────
header "5. Account Password Policy"

POLICY=$($AWS iam get-account-password-policy 2>/dev/null || echo "none")

if [[ "$POLICY" == "none" ]]; then
  critical "No account password policy set"
else
  MIN_LENGTH=$(echo "$POLICY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PasswordPolicy',{}).get('MinimumPasswordLength',0))" 2>/dev/null || echo "0")
  REUSE=$(echo "$POLICY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PasswordPolicy',{}).get('PasswordReusePrevention',0))" 2>/dev/null || echo "0")
  MFA_DELETE=$(echo "$POLICY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('PasswordPolicy',{}).get('HardExpiry','false'))" 2>/dev/null || echo "false")

  [[ $MIN_LENGTH -lt 14 ]] && warning "Password minimum length is $MIN_LENGTH (recommend 14+)" || pass "Password minimum length is $MIN_LENGTH"
  [[ $REUSE -lt 5 ]] && warning "Password reuse prevention is $REUSE (recommend 5+)" || pass "Password reuse prevention: $REUSE previous passwords"
fi

# ─── 6. IAM Access Analyzer ───────────────────────────────────────────────────
header "6. IAM Access Analyzer"

ANALYZER=$($AWS accessanalyzer list-analyzers \
  --query 'analyzers[?status==`ACTIVE`].name' --output text 2>/dev/null || echo "")

if [[ -z "$ANALYZER" ]]; then
  warning "No active IAM Access Analyzer found in region $REGION"
else
  pass "IAM Access Analyzer active: $ANALYZER"
  FINDINGS=$($AWS accessanalyzer list-findings \
    --analyzer-name "$ANALYZER" \
    --filter '{"status": {"eq": ["ACTIVE"]}}' \
    --query 'length(findings)' --output text 2>/dev/null || echo "0")
  [[ $FINDINGS -gt 0 ]] && warning "$FINDINGS active findings in Access Analyzer — review them" \
    || pass "No active findings in Access Analyzer"
fi

# ─── 7. CloudTrail ────────────────────────────────────────────────────────────
header "7. CloudTrail"

TRAILS=$($AWS cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]' \
  --output text 2>/dev/null || echo "")

if [[ -z "$TRAILS" ]]; then
  critical "No CloudTrail trails found"
else
  echo "$TRAILS" | while read -r name multi_region validation; do
    [[ "$multi_region" == "False" ]] && warning "Trail '$name' is not multi-region" \
      || pass "Trail '$name' is multi-region"
    [[ "$validation" == "False" ]] && warning "Trail '$name' has log file validation disabled" \
      || pass "Trail '$name' has log file validation enabled"
  done
fi

# ─── 8. GuardDuty ─────────────────────────────────────────────────────────────
header "8. GuardDuty"

GD_STATUS=$($AWS guardduty list-detectors \
  --query 'DetectorIds' --output text 2>/dev/null || echo "")

if [[ -z "$GD_STATUS" ]]; then
  critical "GuardDuty is not enabled in region $REGION"
else
  for detector_id in $GD_STATUS; do
    STATUS=$($AWS guardduty get-detector --detector-id "$detector_id" \
      --query 'Status' --output text 2>/dev/null || echo "DISABLED")
    [[ "$STATUS" == "ENABLED" ]] && pass "GuardDuty detector $detector_id is ENABLED" \
      || critical "GuardDuty detector $detector_id is DISABLED"
  done
fi

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