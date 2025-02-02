#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

. "${script_dir}"/../../../dashboards/perses_cli.sh
. "${script_dir}/deploy_prometheus.sh"

VERSION="0.50.1"
REPO=https://github.com/perses/perses

tmp_dir=$(mktemp -d -t perses-XXXXXXXXXX)
trap cleanup EXIT

function cleanup() {
    echo "Cleanup"
    rm -rf -- "$tmp_dir"
}

fetch_percli ${REPO} ${VERSION} "${tmp_dir}"

dashboards_dir="${script_dir}/../../../dashboards/loadbalancer/perses"

MONITORING_NS=monitoring
PERCLI=${tmp_dir}/percli
PERSES_SIDECAR=false
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
    --set sidecar.enabled=${PERSES_SIDECAR}

# wait for the perses service to become available
echo "Waiting for the perses service to become available..."
kubectl rollout status --watch --timeout=600s statefulset/perses -n ${MONITORING_NS}

# port-forward the perses service
kubectl port-forward svc/perses -n ${MONITORING_NS} ${PERSES_FWD_PORT}:8080 &
PORT_FORWARD_PID=$!

# wait for svc/perses to be responsive
while ! curl -s http://localhost:${PERSES_FWD_PORT} > /dev/null; do
    echo "Waiting for perses service to be responsive..."
    sleep 5
done

# apply the resources
${PERCLI} login http://localhost:${PERSES_FWD_PORT}
${PERCLI} apply -f ${dashboards_dir}/project.yaml
${PERCLI} apply -f ${dashboards_dir}/datasource.yaml
${PERCLI} apply -f ${dashboards_dir}/lb.yaml
${PERCLI} apply -f ${dashboards_dir}/operator.yaml
${PERCLI} apply -f ${dashboards_dir}/t2.yaml

echo "To access the Perses UI at http://localhost:${PERSES_FWD_PORT} execute:"
echo "   kubectl port-forward svc/perses -n ${MONITORING_NS} ${PERSES_FWD_PORT}:8080"

# Function to clean up background processes
cleanup() {
    echo "Cleaning up..."
    kill ${PORT_FORWARD_PID}
}

# Trap EXIT signal to run cleanup function
trap cleanup EXIT
