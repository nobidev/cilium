#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define T1 and T2 nodes

kubectl label node kind-control-plane lb.cilium.io/tier=t1
kubectl label node kind-worker lb.cilium.io/tier=t2
kubectl label node kind-worker2 lb.cilium.io/tier=t2

# Allow privileged ports (Envoy)
# TODO: configure helm chart accordingly

kind get nodes --name kind | xargs -I container_name docker exec container_name sysctl -w net.ipv4.ip_unprivileged_port_start=0

# Remove Kubeproxy

kubectl -n kube-system delete ds kube-proxy 2>/dev/null || true

# T1 nodeconfig

kubectl apply -f ${script_dir}/manifests/t1-nodeconfig.yml

CILIUM_T1_POD=$(kubectl get pod -l k8s-app=cilium -n kube-system --field-selector spec.nodeName=kind-control-plane -o name)
kubectl delete -n kube-system ${CILIUM_T1_POD}

