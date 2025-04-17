#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define T1 and T2 nodes
t1Nodes=()
t2Nodes=()
t1t2Nodes=()

lbMode="${1-standalone}"
echo "Using '${lbMode}' mode"

if [ "${lbMode}" = "in-cluster" ]; then
  t1t2Nodes+=('kind-control-plane')
  t1t2Nodes+=('kind-worker')
  t1t2Nodes+=('kind-worker2')
  t1t2Nodes+=('kind-worker3')
  t1t2Nodes+=('kind-worker4')
else
  t1Nodes+=('kind-control-plane')
  t1Nodes+=('kind-worker')
  t2Nodes+=('kind-worker2')
  t2Nodes+=('kind-worker3')
  t2Nodes+=('kind-worker4')
fi

for i in "${t1Nodes[@]}"; do
  kubectl label node ${i} service.cilium.io/node=t1 --overwrite
done
for i in "${t2Nodes[@]}"; do
  kubectl label node ${i} service.cilium.io/node=t2 --overwrite
done
for i in "${t1t2Nodes[@]}"; do
  kubectl label node ${i} service.cilium.io/node=t1-t2 --overwrite
done

# Allow privileged ports (Envoy)
kind get nodes --name kind | xargs -I container_name docker exec container_name sysctl -w net.ipv4.ip_unprivileged_port_start=0
