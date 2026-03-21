#!/usr/bin/env bash
# audit-network.sh — VPC and network security audit script
# Usage: ./audit-network.sh [--profile <aws-profile>] [--region <region>]

set -euo pipefail

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

critical() { echo -e "${RED}[CRITICAL]${RESET} $1"; ((CRITICAL_COUNT++)); }
warning()  { echo -e "${YELLOW}[WARNING] ${RESET} $1"; ((WARNING_COUNT++)); }
pass()     { echo -e "${GREEN}[PASS]    ${RESET} $1"; }
info()     { echo -e "${CYAN}[INFO]    ${RESET} $1"; }
header()   { echo -e "\n${BOLD}══════════════════════════════════════════${RESET}"; \
             echo -e "${BOLD}  $1${RESET}"; \
             echo -e "${BOLD}══════════════════════════════════════════${RESET}"; }

# ─── 1. VPC Flow Logs ─────────────────────────────────────────────────────────
header "1. VPC Flow Logs"

VPCS=$($AWS ec2 describe-vpcs \
  --query 'Vpcs[*].[VpcId,Tags[?Key==`Name`].Value|[0],IsDefault]' \
  --output text 2>/dev/null || echo "")

if [[ -z "$VPCS" ]]; then
  info "No VPCs found in region $REGION"
else
  while IFS=$'\t' read -r vpc_id vpc_name is_default; do
    vpc_name="${vpc_name:-unnamed}"

    FLOW_LOG=$($AWS ec2 describe-flow-logs \
      --filter "Name=resource-id,Values=$vpc_id" \
      --query 'FlowLogs[?DeliverLogsStatus==`SUCCESS`].FlowLogId' \
      --output text 2>/dev/null || echo "")

    if [[ -z "$FLOW_LOG" ]]; then
      [[ "$is_default" == "True" ]] && \
        warning "Default VPC $vpc_id has no flow logs enabled" || \
        critical "VPC $vpc_id ($vpc_name) has no flow logs enabled"
    else
      pass "VPC $vpc_id ($vpc_name) has flow logs: $FLOW_LOG"
    fi
  done <<< "$VPCS"
fi

# ─── 2. VPC Endpoints ─────────────────────────────────────────────────────────
header "2. VPC Endpoints"

while IFS=$'\t' read -r vpc_id vpc_name _; do
  vpc_name="${vpc_name:-unnamed}"

  # Check S3 gateway endpoint
  S3_EP=$($AWS ec2 describe-vpc-endpoints \
    --filters \
      "Name=vpc-id,Values=$vpc_id" \
      "Name=service-name,Values=com.amazonaws.$REGION.s3" \
      "Name=state,Values=available" \
    --query 'VpcEndpoints[*].VpcEndpointId' --output text 2>/dev/null || echo "")

  [[ -n "$S3_EP" ]] && pass "VPC $vpc_id ($vpc_name) has S3 gateway endpoint: $S3_EP" \
    || warning "VPC $vpc_id ($vpc_name) has no S3 VPC endpoint — S3 traffic goes over public internet"

  # Check DynamoDB gateway endpoint
  DDB_EP=$($AWS ec2 describe-vpc-endpoints \
    --filters \
      "Name=vpc-id,Values=$vpc_id" \
      "Name=service-name,Values=com.amazonaws.$REGION.dynamodb" \
      "Name=state,Values=available" \
    --query 'VpcEndpoints[*].VpcEndpointId' --output text 2>/dev/null || echo "")

  [[ -n "$DDB_EP" ]] && pass "VPC $vpc_id ($vpc_name) has DynamoDB endpoint: $DDB_EP" \
    || info "VPC $vpc_id ($vpc_name) has no DynamoDB endpoint (add if DynamoDB is used)"

  # Check STS interface endpoint
  STS_EP=$($AWS ec2 describe-vpc-endpoints \
    --filters \
      "Name=vpc-id,Values=$vpc_id" \
      "Name=service-name,Values=com.amazonaws.$REGION.sts" \
      "Name=state,Values=available" \
    --query 'VpcEndpoints[*].VpcEndpointId' --output text 2>/dev/null || echo "")

  [[ -n "$STS_EP" ]] && pass "VPC $vpc_id ($vpc_name) has STS endpoint: $STS_EP" \
    || warning "VPC $vpc_id ($vpc_name) has no STS endpoint — stolen credentials usable outside VPC"

done <<< "$VPCS"

# ─── 3. Default VPC ───────────────────────────────────────────────────────────
header "3. Default VPC"

DEFAULT_VPC=$($AWS ec2 describe-vpcs \
  --filters "Name=isDefault,Values=true" \
  --query 'Vpcs[*].VpcId' --output text 2>/dev/null || echo "")

if [[ -n "$DEFAULT_VPC" ]]; then
  warning "Default VPC $DEFAULT_VPC exists — consider deleting if unused (resources launched here get public IPs by default)"
else
  pass "Default VPC has been deleted"
fi

# ─── 4. Overly Permissive Security Groups ─────────────────────────────────────
header "4. Security Groups — All Traffic Open"

# Find SGs allowing all inbound from anywhere
ALL_INBOUND=$($AWS ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissions[?IpProtocol==`-1` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,VpcId]' \
  --output text 2>/dev/null || echo "")

if [[ -n "$ALL_INBOUND" ]]; then
  while IFS=$'\t' read -r sg_id sg_name vpc_id; do
    critical "Security group $sg_id ($sg_name) in VPC $vpc_id allows ALL inbound traffic from 0.0.0.0/0"
  done <<< "$ALL_INBOUND"
else
  pass "No security groups allow all inbound traffic from 0.0.0.0/0"
fi

# Find SGs allowing all outbound (common but worth flagging)
ALL_OUTBOUND=$($AWS ec2 describe-security-groups \
  --query 'SecurityGroups[?IpPermissionsEgress[?IpProtocol==`-1` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
  --output text 2>/dev/null || echo "")

OUTBOUND_COUNT=$(echo "$ALL_OUTBOUND" | grep -c . 2>/dev/null || echo "0")
[[ $OUTBOUND_COUNT -gt 0 ]] && \
  info "$OUTBOUND_COUNT security groups allow all outbound traffic (default AWS behavior — review for sensitive workloads)"

# ─── 5. S3 Bucket Public Access ───────────────────────────────────────────────
header "5. S3 — Public Access Block"

# Check account-level public access block
ACCOUNT_BLOCK=$($AWS s3control get-public-access-block \
  --account-id $($AWS sts get-caller-identity --query 'Account' --output text) \
  --query 'PublicAccessBlockConfiguration' 2>/dev/null || echo "none")

if [[ "$ACCOUNT_BLOCK" == "none" ]]; then
  critical "S3 account-level public access block is NOT configured"
else
  BLOCK_ALL=$(echo "$ACCOUNT_BLOCK" | python3 -c "
import sys, json
d = json.load(sys.stdin)
all_blocked = all([
  d.get('BlockPublicAcls', False),
  d.get('IgnorePublicAcls', False),
  d.get('BlockPublicPolicy', False),
  d.get('RestrictPublicBuckets', False)
])
print('true' if all_blocked else 'false')
" 2>/dev/null || echo "false")

  [[ "$BLOCK_ALL" == "true" ]] && pass "S3 account-level public access block is fully enabled" \
    || warning "S3 account-level public access block is partially configured — check settings"
fi

# Check individual buckets for public access
info "Checking individual S3 buckets for public access..."
$AWS s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null | \
  tr '\t' '\n' | while read -r bucket; do
  [[ -z "$bucket" ]] && continue

  PUBLIC=$($AWS s3api get-bucket-policy-status \
    --bucket "$bucket" \
    --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "false")

  [[ "$PUBLIC" == "true" ]] && critical "S3 bucket '$bucket' is PUBLICLY ACCESSIBLE via bucket policy"
done

# ─── 6. CloudTrail Multi-Region ───────────────────────────────────────────────
header "6. CloudTrail Coverage"

$AWS cloudtrail describe-trails \
  --query 'trailList[*].[Name,IsMultiRegionTrail,IncludeGlobalServiceEvents,LogFileValidationEnabled]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r name multi_region global_events validation; do
  [[ -z "$name" ]] && continue
  [[ "$multi_region" == "False" ]] && warning "Trail '$name' is single-region — activity in other regions won't be logged"
  [[ "$global_events" == "False" ]] && warning "Trail '$name' doesn't log global service events (IAM, STS, CloudFront)"
  [[ "$validation" == "False" ]] && warning "Trail '$name' log validation disabled — logs could be tampered without detection"
  [[ "$multi_region" == "True" && "$validation" == "True" ]] && pass "Trail '$name' is multi-region with validation enabled"
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
