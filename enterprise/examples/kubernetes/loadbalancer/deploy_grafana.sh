#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "${script_dir}/deploy_prometheus.sh"

kubectl create namespace monitoring || true

kubectl -n monitoring create configmap grafana-dashboards \
	--from-file=lb.json=enterprise/dashboards/loadbalancer/grafana/lb.json
kubectl -n monitoring label configmap grafana-dashboards grafana_dashboard=1

# deploy prometheus and grafana
deploy_prometheus true


helm repo add isovalent https://helm.isovalent.com
helm repo update

# deploy cilium EE dashboards
helm upgrade --install cilium-ee-dashboards \
  isovalent/cilium-ee-dashboards \
  -n monitoring \
  --values "${script_dir}"/manifests/dashboards-values.yaml
