#!/bin/bash
set -euo pipefail

ROUTE_SERVER_ID="${1:?Usage: $0 ROUTE_SERVER_ID [CLUSTER_NAME]}"
CLUSTER_NAME="${2:-egw-test}"

echo "[1/6] Checkin Route Server State for ID $ROUTE_SERVER_ID..."
ROUTE_SERVER_STATE=$(aws ec2 describe-route-servers \
  --route-server-ids "$ROUTE_SERVER_ID" \
  --query 'RouteServers[0].State' \
  --output text 2>/dev/null || echo "not-found")

if [[ "$ROUTE_SERVER_STATE" == "not-found" || "$ROUTE_SERVER_STATE" == "deleted" || "$ROUTE_SERVER_STATE" == "deleting" ]]; then
  echo "Route Server ID '${ROUTE_SERVER_ID}' is already deleted, deleting, or does not exist. Nothing to do."
  exit 0
fi

echo "[2/6] Getting VPC ID for cluster: $CLUSTER_NAME..."
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=tag:eksctl.cluster.k8s.io/v1alpha1/cluster-name,Values=$CLUSTER_NAME" \
  --query "Vpcs[0].VpcId" \
  --output text)

if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  echo "VPC not found for cluster $CLUSTER_NAME"
  exit 1
fi

echo "[3/6] Disabling only active route propagations..."
RTB_IDS=$(aws ec2 get-route-server-propagations \
  --route-server-id "$ROUTE_SERVER_ID" \
  --query "RouteServerPropagations[?State=='available'].RouteTableId" \
  --output text)

for rtb_id in $RTB_IDS; do
  aws ec2 disable-route-server-propagation \
    --route-table-id "$rtb_id" \
    --route-server-id "$ROUTE_SERVER_ID"
done

echo "[4/6] Deleting Route Server Peers..."
PEER_IDS=$(aws ec2 describe-route-server-peers \
  --filters "Name=RouteServerId,Values=$ROUTE_SERVER_ID" \
  --query "RouteServerPeers[?State=='available'].RouteServerPeerId" \
  --output text)

for peer_id in $PEER_IDS; do
  aws ec2 delete-route-server-peer --route-server-peer-id "$peer_id"
done

for peer_id in $PEER_IDS; do
  echo "Waiting for Peer ($peer_id) to be deleted..."
  for _ in {1..30}; do
    STATE=$(aws ec2 describe-route-server-peers \
      --route-server-peer-ids "$peer_id" \
      --query "RouteServerPeers[0].State" \
      --output text 2>/dev/null || echo "deleted")

    if [[ "$STATE" == "deleted" || "$STATE" == "None" ]]; then
      echo "Peer is deleted."
      break
    fi

    echo "  Still '$STATE'... retrying in 10s"
    sleep 10
  done

  if [[ "$STATE" != "deleted" && "$STATE" != "None" ]]; then
    echo "Timed out waiting for Peer $peer_id to be deleted"
    exit 1
  fi
done

echo "[5/6] Deleting Route Server Endpoints..."
ENDPOINT_IDS=$(aws ec2 describe-route-server-endpoints \
  --filters "Name=RouteServerId,Values=$ROUTE_SERVER_ID" \
  --query "RouteServerEndpoints[?State=='available'].RouteServerEndpointId" \
  --output text)

for endpoint_id in $ENDPOINT_IDS; do
  aws ec2 delete-route-server-endpoint --route-server-endpoint-id "$endpoint_id"

  echo "Waiting for Endpoint ($endpoint_id) to be deleted..."
  for _ in {1..30}; do
    STATE=$(aws ec2 describe-route-server-endpoints \
      --route-server-endpoint-ids "$endpoint_id" \
      --query "RouteServerEndpoints[0].State" \
      --output text 2>/dev/null || echo "deleted")

    if [[ "$STATE" == "deleted" || "$STATE" == "None" ]]; then
      echo "Endpoint is deleted."
      break
    fi

    echo "  Still '$STATE'... retrying in 10s"
    sleep 10
  done

  if [[ "$STATE" != "deleted" && "$STATE" != "None" ]]; then
    echo "Timed out waiting for Endpoint to be deleted"
    exit 1
  fi
done

echo "[6/6] Disassociating and deleting Route Server..."
aws ec2 disassociate-route-server \
  --route-server-id "$ROUTE_SERVER_ID" \
  --vpc-id "$VPC_ID"

aws ec2 delete-route-server --route-server-id "$ROUTE_SERVER_ID"

echo "Route Server cleanup complete."
