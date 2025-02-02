#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KUBE_PROMETHEUS_STACK_VERSION="62.7.0"

function deploy_prometheus() {
    grafana_enabled=$1

    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update

    kubectl create namespace monitoring || true

    # deploy prometheus and optionally enabling grafana
    helm upgrade --install prometheus \
        prometheus-community/kube-prometheus-stack \
        --version ${KUBE_PROMETHEUS_STACK_VERSION} \
        -n monitoring \
        --values "${script_dir}"/manifests/prometheus-stack-values.yaml \
        --set grafana.enabled=${grafana_enabled}
}
