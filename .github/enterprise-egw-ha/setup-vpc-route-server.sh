#!/bin/bash
set -euo pipefail

CLUSTER_NAME=${1:-egw-test}
AWS_ASN=${2:-65000}
PEER_ASN=${3:-65001}
ENABLE_BFD=${4:-false}

echo "[1/8] Creating Route Server with ASN $AWS_ASN..."
ROUTE_SERVER_ID=$(aws ec2 create-route-server --amazon-side-asn "$AWS_ASN" \
  --query 'RouteServer.RouteServerId' --output text)

if [[ -z "$ROUTE_SERVER_ID" ]]; then
  echo "Failed to create Route Server with ASN $AWS_ASN"
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "route_server_id=$ROUTE_SERVER_ID" >> "$GITHUB_OUTPUT"
fi

VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:eksctl.cluster.k8s.io/v1alpha1/cluster-name,Values=$CLUSTER_NAME" \
  --query "Vpcs[0].VpcId" \
  --output text)

if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  echo "No VPC found for cluster $CLUSTER_NAME"
  exit 1
fi

echo "[2/8] Associating VPC with Route Server..."
aws ec2 associate-route-server --route-server-id "$ROUTE_SERVER_ID" --vpc-id "$VPC_ID"

get_subnet_id_from_node() {
  LABEL=$1
  node=$(kubectl get nodes -l "$LABEL" -o jsonpath='{.items[0].metadata.name}')
  if [[ -z "$node" ]]; then
    echo "No node found with label: $LABEL" >&2
    return 1
  fi

  instance_id=$(kubectl get node "$node" -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
  if [[ -z "$instance_id" ]]; then
    echo "Failed to get instance ID from node $node" >&2
    return 1
  fi

  subnet_id=$(aws ec2 describe-instances \
    --instance-ids "$instance_id" \
    --query "Reservations[0].Instances[0].SubnetId" \
    --output text)

  if [[ -z "$subnet_id" || "$subnet_id" == "None" ]]; then
    echo "Failed to get subnet ID for instance $instance_id" >&2
    return 1
  fi

  echo "$subnet_id"
}

if ! EGW_NODE_SUBNET_ID=$(get_subnet_id_from_node "egress-group=test"); then
  echo "Failed to get subnet for egw-node"
  exit 1
fi

echo "[3/8] Creating Route Server Endpoint for Subnet: $EGW_NODE_SUBNET_ID..."
RSE_ID=$(aws ec2 create-route-server-endpoint \
  --route-server-id "$ROUTE_SERVER_ID" \
  --subnet-id "$EGW_NODE_SUBNET_ID" \
  --query "RouteServerEndpoint.RouteServerEndpointId" \
  --output text)

echo "Waiting for Route Server Endpoint ($RSE_ID) to become 'available'..."
for _ in {1..30}; do
  STATE=$(aws ec2 describe-route-server-endpoints \
    --route-server-endpoint-ids "$RSE_ID" \
    --query "RouteServerEndpoints[0].State" \
    --output text)
  if [[ "$STATE" == "available" ]]; then
    echo "Route Server Endpoint is available."
    break
  fi
  echo "  Still '$STATE'... retrying in 10s"
  sleep 10
done

if [[ "$STATE" != "available" ]]; then
  echo "Timed out waiting for Route Server Endpoint to become 'available'"
  exit 1
fi

if ! NO_CILIUM_SUBNET_ID=$(get_subnet_id_from_node "cilium.io/no-schedule=true"); then
  echo "Failed to get subnet for no-schedule node"
  exit 1
fi
SUBNET_IDS=("$EGW_NODE_SUBNET_ID" "$NO_CILIUM_SUBNET_ID")

ROUTE_TABLE_IDS=()
for subnet_id in "${SUBNET_IDS[@]}"; do
  rtb_id=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=$subnet_id" \
    --query "RouteTables[0].RouteTableId" \
    --output text 2>/dev/null)

  if [[ "$rtb_id" != "None" && -n "$rtb_id" ]]; then
    ROUTE_TABLE_IDS+=("$rtb_id")
  else
    echo "Skipping Subnet $subnet_id (no explicit route table association)"
  fi
done

echo "[4/8] Enabling Route Server Propagation..."
for rtb_id in "${ROUTE_TABLE_IDS[@]}"; do
  aws ec2 enable-route-server-propagation \
    --route-table-id "$rtb_id" \
    --route-server-id "$ROUTE_SERVER_ID"
done

echo "[5/8] Creating BGP Peers... (BFD enabled: $ENABLE_BFD)"
RR_NODE_IPS=$(kubectl get nodes -l "rr-role=route-reflector" -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')

for ip in $RR_NODE_IPS; do
  echo "  Creating peer for $ip"
  if [[ "$ENABLE_BFD" == "true" ]]; then
    aws ec2 create-route-server-peer \
      --route-server-endpoint-id "$RSE_ID" \
      --peer-address "$ip" \
      --bgp-options PeerAsn="$PEER_ASN",PeerLivenessDetection=bfd
  else
    aws ec2 create-route-server-peer \
      --route-server-endpoint-id "$RSE_ID" \
      --peer-address "$ip" \
      --bgp-options PeerAsn="$PEER_ASN"
  fi
done

echo "Waiting for Route Server Peers to become 'available'..."
for _ in {1..30}; do
  STATES=$(aws ec2 describe-route-server-peers \
    --filters "Name=RouteServerId,Values=$ROUTE_SERVER_ID" \
    --query 'RouteServerPeers[*].State' \
    --output text)

  NOT_READY=0
  for state in $STATES; do
    if [[ "$state" != "available" ]]; then
      NOT_READY=1
      break
    fi
  done

  if [[ "$NOT_READY" -eq 0 ]]; then
    echo "All peers are available."
    break
  fi

  echo "Some peers are not available yet: $STATES"
  sleep 10
done

echo "[6/8] Disabling Source/Dest Check on ENIs..."
disable_src_dst_check_for_label() {
  LABEL=$1
  NODE_NAMES=$(kubectl get nodes -l "$LABEL" -o jsonpath='{.items[*].metadata.name}')

  for node in $NODE_NAMES; do
    instance_id=$(kubectl get node "$node" -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)
    eni_id=$(aws ec2 describe-instances \
      --instance-ids "$instance_id" \
      --query "Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId" \
      --output text)

    aws ec2 modify-network-interface-attribute \
      --network-interface-id "$eni_id" \
      --source-dest-check "{\"Value\": false}"
  done
}

disable_src_dst_check_for_label "egress-group=test"
disable_src_dst_check_for_label "cilium.io/no-schedule=true"

echo "[7/8] Allowing UDP port 3784..."
mapfile -t NODE_NAMES < <(kubectl get nodes -l "egress-group=test" -o name | sed 's|^node/||')

if [[ ${#NODE_NAMES[@]} -eq 0 ]]; then
  echo "No nodes found with label egress-group=test"
  exit 1
fi

INSTANCE_ID=$(kubectl get node "${NODE_NAMES[0]}" -o jsonpath='{.spec.providerID}' | cut -d'/' -f5)

SG_IDS=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --query "Reservations[].Instances[].SecurityGroups[].GroupId" \
  --output text)

if [[ -z "${SG_IDS// }" || "$SG_IDS" == "None" ]]; then
  echo "No Security Groups found for instance $INSTANCE_ID"
  exit 1
fi

RS_IP=$(aws ec2 describe-route-server-endpoints \
  --query "RouteServerEndpoints[?RouteServerEndpointId=='${RSE_ID}'].EniAddress" \
  --output text)

for sg_id in $SG_IDS; do
  aws ec2 authorize-security-group-ingress \
    --group-id "$sg_id" \
    --protocol udp \
    --port 3784 \
    --cidr "${RS_IP}/32" \
    || echo "Skipped (already exists or failed)"
done

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "route_server_endpoint_ip=$RS_IP" >> "$GITHUB_OUTPUT"
fi

echo "[8/8] Full setup completed. Route server endpoint ip: $RS_IP"
