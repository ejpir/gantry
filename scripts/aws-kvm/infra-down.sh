#!/bin/bash
# infra-down.sh — stop the meter running. Default: STOP the instance and
# DELETE the SSM interface endpoints (the ~$22/mo items). Keeps the
# bucket, IAM role, SGs, and the free S3 gateway endpoint.
#   infra-down.sh --terminate   also terminates the instance
#   infra-down.sh --keep-vpce   keeps the SSM interface endpoints
set -euo pipefail

REGION="${REGION:-eu-west-1}"
NAME=gantry-kvm-test
export AWS_DEFAULT_REGION="$REGION"
TERMINATE=0; KEEP_VPCE=0
for a in "$@"; do case "$a" in --terminate) TERMINATE=1;; --keep-vpce) KEEP_VPCE=1;; esac; done

IID=$(aws ec2 describe-instances --filters Name=tag:Name,Values="$NAME" Name=instance-state-name,Values=pending,running,stopping,stopped \
      --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)
if [ -n "$IID" ] && [ "$IID" != "None" ]; then
	if [ "$TERMINATE" = 1 ]; then
		aws ec2 terminate-instances --instance-ids "$IID" >/dev/null && echo "terminated $IID"
	else
		aws ec2 stop-instances --instance-ids "$IID" >/dev/null 2>&1 && echo "stopped $IID" || echo "$IID not running"
	fi
else
	echo "no instance found"
fi

if [ "$KEEP_VPCE" = 0 ]; then
	for svc in ssm ssmmessages ec2messages; do
		ID=$(aws ec2 describe-vpc-endpoints --filters Name=service-name,Values="com.amazonaws.$REGION.$svc" \
		     --query 'VpcEndpoints[0].VpcEndpointId' --output text 2>/dev/null || true)
		[ -n "$ID" ] && [ "$ID" != "None" ] && aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$ID" >/dev/null && echo "deleted $svc endpoint $ID"
	done
else
	echo "keeping interface endpoints"
fi
echo "done. (kept: staging bucket, role gantry-ssm-ec2, SGs, S3 gateway endpoint)"
