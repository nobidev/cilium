#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "${script_dir}/deploy_prometheus.sh"

VERSION="0.50.1"
REPO=https://github.com/perses/perses

dashboards_dir="${script_dir}/../../../dashboards/loadbalancer/perses"

MONITORING_NS=monitoring
PERSES_SIDECAR=true
PERSES_FWD_PORT=8080

# verify we have helm
if ! command -v helm &> /dev/null
then
    echo "helm could not be found, please install it first."
    exit 1
fi

# make sure we have the relevant repos
helm repo add perses https://perses.github.io/helm-charts
helm repo update

# deploy prometheus only
deploy_prometheus false

# deploy perses
helm upgrade --install --wait --timeout 5m perses perses/perses \
    -n ${MONITORING_NS} \
    --set image.version="v${VERSION}" \
    --set sidecar.enabled=${PERSES_SIDECAR} \
    --set config.provisioning.interval=10s

# wait for the perses service to become available
echo "Waiting for the perses service to become available..."
kubectl rollout status --watch --timeout=600s statefulset/perses -n ${MONITORING_NS}

echo "Installing Perses Resources"
for f in "$dashboards_dir"/*.yaml; do
  basename="$(basename $f)"
  name="perses-${basename%.*}"

  kubectl create configmap "$name" \
    --namespace ${MONITORING_NAMESPACE} \
    --from-file="$f" || \
    echo "There was already a ConfigMap named $name"

  kubectl label configmap "$name" \
    --namespace ${MONITORING_NAMESPACE} \
    --overwrite \
    perses.dev/resource=true
done

echo "To access the Perses UI at http://localhost:${PERSES_FWD_PORT} execute:"
echo "   kubectl port-forward svc/perses -n ${MONITORING_NS} ${PERSES_FWD_PORT}:8080"
