#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/common.sh"

# Define T1 and T2 nodes

t1Nodes=(
  kind-control-plane
  kind-worker
)
t2Nodes=(
  kind-worker2
  kind-worker3
  kind-worker4
)

for i in "${t1Nodes[@]}"; do
  kubectl label node ${i} service.cilium.io/node=t1
  kubectl taint node ${i} service.cilium.io/node=t1:NoSchedule
done
for i in "${t2Nodes[@]}"; do
  kubectl label node ${i} service.cilium.io/node=t2
done

# Allow privileged ports (Envoy)

kind get nodes --name kind | xargs -I container_name docker exec container_name sysctl -w net.ipv4.ip_unprivileged_port_start=0

# Remove Kubeproxy

kubectl -n kube-system delete ds kube-proxy 2>/dev/null || true

echo -n "Waiting for CRDs "
crds=(
  "ciliumnodeconfigs.cilium.io"
  "ciliumloadbalancerippools.cilium.io"
  "ciliumbgppeeringpolicies.cilium.io"
  "isovalentbfdprofiles.isovalent.com"
  "lbservices.isovalent.com"
  "lbbackendpools.isovalent.com"
  "lbvips.isovalent.com"
)
for crd in "${crds[@]}"; do
  while ! kubectl get crd "${crd}" &>/dev/null; do
    echo -n "."
    sleep 2
  done
done
echo ""

# T1 nodeconfig
kubectl apply -f "${script_dir}/lb/t1-nodeconfig.yaml"

t1NodeNames=$(kubectl get nodes -l service.cilium.io/node=t1 -oyaml | yq_run '.items[].metadata.name')
for i in $(echo $t1NodeNames); do
  CILIUM_T1_POD=$(kubectl get pod -l k8s-app=cilium -n kube-system --field-selector spec.nodeName="${i}" -o name)
  kubectl delete -n kube-system "${CILIUM_T1_POD}"
done

# restart coredns pods to ensure they don't run on tainted T1 nodes
kubectl -n kube-system delete pods -l k8s-app=kube-dns

# Wait until LB nodes are ready
echo -n "Waiting until LB nodes are ready ..."
cilium status --wait --interactive=false --ignore-warnings
