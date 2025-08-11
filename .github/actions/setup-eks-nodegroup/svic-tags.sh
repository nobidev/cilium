#!/usr/bin/env bash

# Copyright (C) Isovalent, Inc. - All Rights Reserved.

set -o errexit
set -o pipefail
set -o nounset

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <CLUSTER_NAME> <REGION>"
  exit 1
fi

CLUSTER_NAME="$1"
REGION="$2"

# tag cluster
aws eks tag-resource \
  --region "$REGION" \
  --resource-arn "$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$REGION" --query 'cluster.arn' --output text)" \
  --tags svic_falco_supported=no

# tag nodes
NODE_IDS=$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=tag:eks:cluster-name,Values=$CLUSTER_NAME" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' --output text)

if [ -n "$NODE_IDS" ]; then
  aws ec2 create-tags \
    --region "$REGION" \
    --resources $NODE_IDS \
    --tags Key=svic_osquery_supported,Value=no
else
  echo "No running nodes found for cluster $CLUSTER_NAME in $REGION"
fi