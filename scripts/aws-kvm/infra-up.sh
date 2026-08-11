#!/bin/bash
# infra-up.sh — create the gantry x86_64 KVM test environment on AWS.
# Idempotent: safe to re-run; existing pieces are reused. Prints the
# instance id last (export it as GANTRY_TEST_IID for ssm.py).
#
# Corporate-VPC notes (eu-west-1, vpc with no IGW + zero-egress default
# SG): we add VPC endpoints for SSM/S3 and our own egress SG. The SSM
# interface endpoints cost ~$7/mo each — infra-down.sh removes them.
#
# Override via env: REGION SUBNET_ID INSTANCE_TYPE BUCKET
set -euo pipefail

REGION="${REGION:-eu-west-1}"
SUBNET_ID="${SUBNET_ID:?set SUBNET_ID to a subnet in your VPC (aws ec2 describe-subnets)}"
INSTANCE_TYPE="${INSTANCE_TYPE:-c5.metal}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET="${BUCKET:-gantry-kvm-test-$ACCOUNT}"
ROLE=gantry-ssm-ec2
NAME=gantry-kvm-test
export AWS_DEFAULT_REGION="$REGION"

echo "== bucket =="
aws s3 mb "s3://$BUCKET" --region "$REGION" 2>/dev/null || echo "bucket exists"

echo "== IAM role + instance profile =="
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
	aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
	  "Version":"2012-10-17","Statement":[{"Effect":"Allow",
	  "Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
	aws iam attach-role-policy --role-name "$ROLE" \
	  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
fi
aws iam create-instance-profile --instance-profile-name "$ROLE" >/dev/null 2>&1 || true
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE" 2>/dev/null || true

VPC_ID=$(aws ec2 describe-subnets --subnet-ids "$SUBNET_ID" --query 'Subnets[0].VpcId' --output text)
RTB=$(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC_ID" Name=association.main,Values=true \
      --query 'RouteTables[0].RouteTableId' --output text)
echo "== vpc: $VPC_ID (main rtb $RTB) =="

echo "== security groups =="
VPCE_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=gantry-vpce Name=vpc-id,Values="$VPC_ID" \
          --query 'SecurityGroups[0].GroupId' --output text)
if [ "$VPCE_SG" = "None" ] || [ -z "$VPCE_SG" ]; then
	VPCE_SG=$(aws ec2 create-security-group --group-name gantry-vpce --description "VPCE HTTPS" \
	          --vpc-id "$VPC_ID" --query 'GroupId' --output text)
	aws ec2 authorize-security-group-ingress --group-id "$VPCE_SG" --protocol tcp --port 443 --cidr 10.0.0.0/8 >/dev/null
fi
TEST_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=gantry-test Name=vpc-id,Values="$VPC_ID" \
          --query 'SecurityGroups[0].GroupId' --output text)
if [ "$TEST_SG" = "None" ] || [ -z "$TEST_SG" ]; then
	TEST_SG=$(aws ec2 create-security-group --group-name gantry-test --description "gantry test egress" \
	          --vpc-id "$VPC_ID" --query 'GroupId' --output text)
	aws ec2 authorize-security-group-egress --group-id "$TEST_SG" --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
fi
echo "vpce-sg=$VPCE_SG test-sg=$TEST_SG"

echo "== VPC endpoints (S3 gateway is free; SSM trio ~\$22/mo) =="
if ! aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values="$VPC_ID" Name=service-name,Values="com.amazonaws.$REGION.s3" \
     --query 'VpcEndpoints[0].VpcEndpointId' --output text 2>/dev/null | grep -q vpce; then
	aws ec2 create-vpc-endpoint --vpc-id "$VPC_ID" --service-name "com.amazonaws.$REGION.s3" \
	  --vpc-endpoint-type Gateway --route-table-ids "$RTB" >/dev/null
fi
for svc in ssm ssmmessages ec2messages; do
	if ! aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values="$VPC_ID" Name=service-name,Values="com.amazonaws.$REGION.$svc" \
	     --query 'VpcEndpoints[0].VpcEndpointId' --output text 2>/dev/null | grep -q vpce; then
		aws ec2 create-vpc-endpoint --vpc-id "$VPC_ID" --service-name "com.amazonaws.$REGION.$svc" \
		  --vpc-endpoint-type Interface --subnet-ids "$SUBNET_ID" --security-group-ids "$VPCE_SG" \
		  --private-dns-enabled >/dev/null
	fi
done

echo "== instance ($INSTANCE_TYPE) =="
IID=$(aws ec2 describe-instances --filters Name=tag:Name,Values="$NAME" Name=instance-state-name,Values=pending,running,stopping,stopped \
      --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)
if [ -z "$IID" ] || [ "$IID" = "None" ]; then
	AMI_PARAM="${AMI_PARAM:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}"
	AMI=$(aws ssm get-parameter --name "$AMI_PARAM" \
	      --query 'Parameter.Value' --output text)
	IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --subnet-id "$SUBNET_ID" \
	      --iam-instance-profile Name="$ROLE" --security-group-ids "$TEST_SG" \
	      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
	      --query 'Instances[0].InstanceId' --output text)
	echo "launched $IID (ami $AMI)"
else
	echo "reusing $IID"
	STATE=$(aws ec2 describe-instances --instance-ids "$IID" --query 'Reservations[0].Instances[0].State.Name' --output text)
	[ "$STATE" = "stopped" ] && aws ec2 start-instances --instance-ids "$IID" >/dev/null && echo "started"
	# make sure our egress SG is attached (default SG has no egress)
	ENI=$(aws ec2 describe-instances --instance-ids "$IID" \
	      --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)
	CUR=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" --query 'NetworkInterfaces[0].Groups[*].GroupId' --output text)
	case " $CUR " in *" $TEST_SG "*) ;; *) aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" --groups $CUR "$TEST_SG";; esac
fi

echo "== waiting for SSM agent =="
for _ in $(seq 1 40); do
	P=$(aws ssm describe-instance-information --filters Key=InstanceIds,Values="$IID" \
	    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
	[ "$P" = "Online" ] && break
	sleep 15
done
[ "$P" = "Online" ] || { echo "SSM agent never came online" >&2; exit 1; }
echo "SSM online"
echo "INSTANCE: $IID"
