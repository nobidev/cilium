#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add isovalent https://helm.isovalent.com
helm repo update

kubectl create namespace monitoring

kubectl -n monitoring create configmap grafana-dashboards \
	--from-file=lb.json=enterprise/grafana/loadbalancer/lb.json \
	--from-file=t2.json=enterprise/grafana/loadbalancer/t2.json
kubectl -n monitoring label configmap grafana-dashboards grafana_dashboard=1

helm upgrade --install prometheus \
  prometheus-community/kube-prometheus-stack \
  --version 62.7.0 \
  -n monitoring \
  --values "${script_dir}"/manifests/prometheus-stack-values.yaml

helm upgrade --install cilium-ee-dashboards \
  isovalent/cilium-ee-dashboards \
  -n monitoring \
  --values "${script_dir}"/manifests/dashboards-values.yaml
