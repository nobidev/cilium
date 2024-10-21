#!/bin/bash

# Usage
#
# ./control.sh [t1-lb|t2-lb|backend] [<cilium-node-name>|<backend-container-name>] [healthcheck|response] [ok|fail]
#
# Change healthcheck state for a backend container
# ./control.sh backend app1 healthcheck fail
#
# Change response state for a backend container
# ./control.sh backend app1 response fail
#
# Change healthcheck state for a T2 loadbalancer instance
# ./control.sh t2-lb cilium-worker2 healthcheck fail
#
# Change healthcheck state for a T1 loadbalancer instance
# ./control.sh t1-lb cilium-control-plane healthcheck fail

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/common.sh"

if [ -z ${1+x} ]; then
  echo "no instance type set [t2-lb|backend]"
  exit 1
fi

if [ -z ${2+x} ]; then
  echo "no instance name set [<cilium-node-name>|<backend-container-name>]"
  exit 1
fi

if [ -z ${3+x} ]; then
  echo "no type set [healthcheck|response]"
  exit 1
fi

if [ -z ${4+x} ]; then
  echo "no status set [ok|fail]"
  exit 1
fi

if [ "$1" = "backend" ]; then
  docker exec "$2" curl -s -X POST "http://localhost:8080/control/$3/$4"

elif [ "$1" = "t2-lb" ]; then
  if [ "$3" = "response" ]; then
    echo "controlling response type currently not possible for t2-lb"
    exit 1
  fi

  agentPod=$(kubectl -n kube-system get pods --field-selector spec.nodeName="${2}" -l k8s-app=cilium -oyaml | yq_run '.items[0].metadata.name')
  kubectl -n kube-system exec "${agentPod}" -c cilium-agent -- apt-get update -qq
  kubectl -n kube-system exec "${agentPod}" -c cilium-agent -- apt-get install -y -qq curl
  kubectl -n kube-system exec "${agentPod}" -c cilium-agent -- curl -X POST -s --unix-socket /var/run/cilium/envoy/sockets/admin.sock http:/admin/"$3"/"$4"
elif [ "$1" = "t1-lb" ]; then
  if [ "$3" = "response" ]; then
    echo "controlling response type currently not possible for t1-lb"
    exit 1
  fi

  agentIP=$(kubectl get nodes "${2}" -ojson | jq -r '.status.addresses[0].address')
  action="A"
  if [ "$4" = "ok" ]; then
    action="D"
  fi
  docker exec kind-worker2 iptables -${action} INPUT -s ${agentIP} -j DROP
  docker exec kind-worker3 iptables -${action} INPUT -s ${agentIP} -j DROP
  docker exec kind-worker4 iptables -${action} INPUT -s ${agentIP} -j DROP
fi
