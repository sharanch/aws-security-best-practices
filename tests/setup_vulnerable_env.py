#!/usr/bin/env python3
"""
setup_vulnerable_env.py
Creates deliberately misconfigured AWS resources against a moto server.
Every resource is designed to trigger a finding in one of the 4 audit scripts.

Usage:
    python3 setup_vulnerable_env.py [--endpoint http://localhost:5000]
"""

import boto3
import json
import sys
import argparse
import zipfile
import io

# ── Colors ────────────────────────────────────────────────────────
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg):   print(f"  {CYAN}>{RESET} {msg}")
def ok(msg):    print(f"  {GREEN}[created]{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}[skip]{RESET}   {msg}")
def header(msg):print(f"\n{BOLD}{msg}{RESET}\n{'─'*50}")

def section(title): header(f"// {title}")

def make_client(service, endpoint, region="ap-south-1"):
    return boto3.client(
        service,
        endpoint_url=endpoint,
        region_name=region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

def make_lambda_zip():
    """Create a minimal valid Lambda zip in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(event, context):\n    return {'statusCode': 200}\n")
    buf.seek(0)
    return buf.read()

ACCOUNT_ID = "123456789012"

def setup_iam(endpoint):
    section("IAM — audit-iam.sh triggers")
    iam = make_client("iam", endpoint)

    # Moto does not pre-load AWS managed policies — create AdministratorAccess manually
    # Use the exact ARN the audit scripts reference: arn:aws:iam::aws:policy/AdministratorAccess
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    try:
        iam.create_policy(
            PolicyName="AdministratorAccess",
            Path="/",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }),
            Description="Provides full access to AWS services and resources (moto mock)",
        )
        ok("AdministratorAccess managed policy created in moto")
    except Exception as e:
        if "EntityAlreadyExists" in str(e):
            warn("AdministratorAccess policy already exists")
        else:
            warn(f"AdministratorAccess policy: {e}")

    # 1. User with no MFA, active access key
    try:
        iam.create_user(UserName="test-no-mfa-user")
        iam.create_access_key(UserName="test-no-mfa-user")
        ok("test-no-mfa-user (no MFA, has access key)")
    except Exception as e:
        warn(f"test-no-mfa-user: {e}")

    # 2. User with AdministratorAccess attached directly
    try:
        iam.create_user(UserName="test-admin-user")
        iam.create_access_key(UserName="test-admin-user")
        iam.attach_user_policy(
            UserName="test-admin-user",
            PolicyArn=admin_policy_arn,
        )
        ok("test-admin-user (AdministratorAccess attached)")
    except Exception as e:
        warn(f"test-admin-user: {e}")

    # 3. Group with AdministratorAccess
    try:
        iam.create_group(GroupName="test-admin-group")
        iam.attach_group_policy(
            GroupName="test-admin-group",
            PolicyArn=admin_policy_arn,
        )
        ok("test-admin-group (AdministratorAccess attached)")
    except Exception as e:
        warn(f"test-admin-group: {e}")

    # 4. Role with Principal: * in trust policy (dangerous)
    try:
        iam.create_role(
            RoleName="test-dangerous-trust-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        ok("test-dangerous-trust-role (Principal: * in trust policy)")
    except Exception as e:
        warn(f"test-dangerous-trust-role: {e}")

    # 5. Role with AdministratorAccess (for EC2 instance profile)
    try:
        iam.create_role(
            RoleName="test-ec2-admin-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        iam.attach_role_policy(
            RoleName="test-ec2-admin-role",
            PolicyArn=admin_policy_arn,
        )
        iam.create_instance_profile(InstanceProfileName="test-ec2-admin-profile")
        iam.add_role_to_instance_profile(
            InstanceProfileName="test-ec2-admin-profile",
            RoleName="test-ec2-admin-role",
        )
        ok("test-ec2-admin-role (AdministratorAccess — for EC2 instance profile)")
    except Exception as e:
        warn(f"test-ec2-admin-role: {e}")

    # 6. Lambda execution role
    try:
        iam.create_role(
            RoleName="test-lambda-role",
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
        )
        iam.attach_role_policy(
            RoleName="test-lambda-role",
            PolicyArn=admin_policy_arn,
        )
        ok("test-lambda-role (AdministratorAccess on Lambda role)")
    except Exception as e:
        warn(f"test-lambda-role: {e}")

def setup_ec2(endpoint):
    section("EC2 — audit-ec2.sh triggers")
    ec2 = make_client("ec2", endpoint)

    # 1. Security group with SSH open to world
    try:
        sg = ec2.create_security_group(
            GroupName="test-open-ssh-sg",
            Description="Audit test: SSH open to world",
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        ok(f"test-open-ssh-sg ({sg_id}) — SSH open to 0.0.0.0/0")
    except Exception as e:
        warn(f"test-open-ssh-sg: {e}")

    # 2. Security group with RDP open to world
    try:
        sg = ec2.create_security_group(
            GroupName="test-open-rdp-sg",
            Description="Audit test: RDP open to world",
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        ok(f"test-open-rdp-sg ({sg_id}) — RDP open to 0.0.0.0/0")
    except Exception as e:
        warn(f"test-open-rdp-sg: {e}")

    # 3. Security group with all traffic open
    try:
        sg = ec2.create_security_group(
            GroupName="test-all-traffic-sg",
            Description="Audit test: all traffic open",
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        ok(f"test-all-traffic-sg ({sg_id}) — all traffic from 0.0.0.0/0")
    except Exception as e:
        warn(f"test-all-traffic-sg: {e}")

    # 4. EC2 instance with IMDSv1 enabled (HttpTokens=optional)
    try:
        # Get first available AMI
        images = ec2.describe_images(
            Filters=[{"Name": "name", "Values": ["amzn2-ami-*"]}],
            Owners=["amazon"],
        )
        ami_id = images["Images"][0]["ImageId"] if images["Images"] else "ami-12345678"

        reservation = ec2.run_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            MetadataOptions={
                "HttpTokens": "optional",   # IMDSv1 — vulnerable
                "HttpEndpoint": "enabled",
            },
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "test-imdsv1-instance"}],
            }],
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        ok(f"test-imdsv1-instance ({instance_id}) — IMDSv1 enabled (HttpTokens=optional)")
    except Exception as e:
        warn(f"test-imdsv1-instance: {e}")

    # 5. EC2 instance with public IP and admin role
    try:
        reservation = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            IamInstanceProfile={"Name": "test-ec2-admin-profile"},
            MetadataOptions={
                "HttpTokens": "optional",
                "HttpEndpoint": "enabled",
            },
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "test-admin-role-instance"}],
            }],
        )
        instance_id = reservation["Instances"][0]["InstanceId"]
        ok(f"test-admin-role-instance ({instance_id}) — has AdministratorAccess role + IMDSv1")
    except Exception as e:
        warn(f"test-admin-role-instance: {e}")

    # 6. Unencrypted EBS volume
    try:
        vol = ec2.create_volume(
            AvailabilityZone="ap-south-1a",
            Size=1,
            Encrypted=False,
            TagSpecifications=[{
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": "test-unencrypted-ebs"}],
            }],
        )
        ok(f"test-unencrypted-ebs ({vol['VolumeId']}) — not encrypted")
    except Exception as e:
        warn(f"test-unencrypted-ebs: {e}")

def setup_network(endpoint):
    section("Network — audit-network.sh triggers")
    ec2 = make_client("ec2", endpoint)

    # Default VPC exists by default in moto — that's a finding already
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    if vpcs["Vpcs"]:
        ok(f"Default VPC exists ({vpcs['Vpcs'][0]['VpcId']}) — triggers 'default VPC present' finding")

    # Create a VPC with no flow logs (flow logs absence = finding)
    try:
        vpc = ec2.create_vpc(CidrBlock="10.99.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": "test-no-flowlogs-vpc"}])
        ok(f"test-no-flowlogs-vpc ({vpc_id}) — no flow logs enabled")
        # No VPC endpoints either = triggers S3/STS endpoint findings
        ok(f"test-no-flowlogs-vpc — no S3/STS/DynamoDB endpoints configured")
    except Exception as e:
        warn(f"test-no-flowlogs-vpc: {e}")

def setup_s3(endpoint, region="ap-south-1"):
    section("S3 — audit-s3-rds.sh triggers")
    s3  = make_client("s3",         endpoint, region)
    s3c = make_client("s3control",  endpoint, region)

    # 1. Public bucket with Principal: * policy
    try:
        bucket = "test-audit-public-bucket"
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
        # Disable block public access
        s3.delete_public_access_block(Bucket=bucket)
        # Attach public policy
        s3.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }],
            }),
        )
        ok(f"{bucket} — PUBLIC (Principal:* with no conditions, BPA disabled)")
    except Exception as e:
        warn(f"test-audit-public-bucket: {e}")

    # 2. Bucket with no encryption, no versioning, no logging
    try:
        bucket = "test-audit-noenc-bucket"
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
        # Don't set encryption or versioning — audit script flags absence
        ok(f"{bucket} — no encryption, no versioning, no access logging")
    except Exception as e:
        warn(f"test-audit-noenc-bucket: {e}")

    # 3. Bucket with no versioning (separate, easy to spot)
    try:
        bucket = "test-audit-novers-bucket"
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
        ok(f"{bucket} — versioning disabled")
    except Exception as e:
        warn(f"test-audit-novers-bucket: {e}")

def setup_rds(endpoint, region="ap-south-1"):
    section("RDS — audit-s3-rds.sh triggers")
    rds = make_client("rds", endpoint, region)

    # 1. Publicly accessible RDS instance, not encrypted
    try:
        rds.create_db_instance(
            DBInstanceIdentifier="test-public-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
            PubliclyAccessible=True,       # triggers public access finding
            StorageEncrypted=False,        # triggers encryption finding
            BackupRetentionPeriod=0,       # triggers backup finding
            MultiAZ=False,
            EnableIAMDatabaseAuthentication=False,
            DeletionProtection=False,
        )
        ok("test-public-db — publicly accessible, not encrypted, no backups, IAM auth off")
    except Exception as e:
        warn(f"test-public-db: {e}")

    # 2. Second instance: encrypted but still public (belt + suspenders)
    try:
        rds.create_db_instance(
            DBInstanceIdentifier="test-public-enc-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername="admin",
            MasterUserPassword="password123",
            AllocatedStorage=20,
            PubliclyAccessible=True,       # still public
            StorageEncrypted=True,
            BackupRetentionPeriod=7,
            MultiAZ=False,
            EnableIAMDatabaseAuthentication=False,
            DeletionProtection=False,
        )
        ok("test-public-enc-db — publicly accessible, IAM auth off, deletion protection off")
    except Exception as e:
        warn(f"test-public-enc-db: {e}")

def setup_lambda(endpoint, region="ap-south-1"):
    section("Lambda — audit-s3-rds.sh triggers")
    lam = make_client("lambda", endpoint, region)
    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/test-lambda-role"
    zip_bytes = make_lambda_zip()

    # Lambda with secrets in env vars
    try:
        lam.create_function(
            FunctionName="test-audit-lambda-secrets",
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Environment={
                "Variables": {
                    "DB_PASSWORD": "super-secret-prod-password",
                    "API_KEY": "sk-live-abc123xyz",
                    "STRIPE_SECRET_KEY": "sk_live_xxxxxxxx",
                    "APP_ENV": "production",      # this one is fine
                }
            },
        )
        ok("test-audit-lambda-secrets — env vars contain DB_PASSWORD, API_KEY, STRIPE_SECRET_KEY")
    except Exception as e:
        warn(f"test-audit-lambda-secrets: {e}")

    # Lambda with public URL (AuthType NONE)
    try:
        lam.create_function(
            FunctionName="test-audit-lambda-public-url",
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
        )
        lam.create_function_url_config(
            FunctionName="test-audit-lambda-public-url",
            AuthType="NONE",    # unauthenticated public URL
        )
        ok("test-audit-lambda-public-url — public Lambda URL with AuthType NONE")
    except Exception as e:
        warn(f"test-audit-lambda-public-url: {e}")

def main():
    parser = argparse.ArgumentParser(description="Create vulnerable AWS resources in moto")
    parser.add_argument("--endpoint", default="http://localhost:5000", help="Moto server endpoint")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}")
    print("  ┌─────────────────────────────────────────────┐")
    print("  │   aws-security-best-practices               │")
    print("  │   Vulnerable Environment Setup              │")
    print("  │   Target: " + args.endpoint.ljust(34) + "│")
    print("  └─────────────────────────────────────────────┘")
    print(f"{RESET}")

    setup_iam(args.endpoint)
    setup_ec2(args.endpoint)
    setup_network(args.endpoint)
    setup_s3(args.endpoint)
    setup_rds(args.endpoint)
    setup_lambda(args.endpoint)

    print(f"\n{BOLD}{GREEN}Done.{RESET} All vulnerable resources created.")
    print(f"\nNow run the audit scripts:")
    print(f"  {CYAN}bash run-audit-local.sh{RESET}")
    print()

if __name__ == "__main__":
    main()