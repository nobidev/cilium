#!/usr/bin/env bash

# Adapted from examples/kubernetes/loadbalancer/example_install.sh

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.
set -x

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_IMG="quay.io/isovalent-dev/lb-healthcheck-app:v0.0.4"

#
# Backends
#

# Backend TLS Secret (for testing TLS passthrough - is mounted and used by test health check backend)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-backend.key" -out "${script_dir}/tls-secure-backend.crt" -subj "/CN=passthrough.acme.io"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-backend2.key" -out "${script_dir}/tls-secure-backend2.crt" -subj "/CN=passthrough-2.acme.io"

# Deploy Test health check backends

docker run -d --name app1 --rm --env SERVICE_NAME=service1 --env INSTANCE_NAME=1 --env H2C_ENABLED=true --network kind-cilium "${APP_IMG}"
docker run -d --name app2 --rm --env SERVICE_NAME=service2 --env INSTANCE_NAME=2 --env H2C_ENABLED=true --network kind-cilium "${APP_IMG}"
docker run -d --name app3 --rm --env SERVICE_NAME=service3 --env INSTANCE_NAME=3 --env H2C_ENABLED=true --network kind-cilium "${APP_IMG}"

TLS_CERT_BASE64_4=$(cat ${script_dir}/tls-secure-backend.crt | base64)
TLS_KEY_BASE64_4=$(cat ${script_dir}/tls-secure-backend.key | base64)
docker run -d --name app4 --rm --env SERVICE_NAME=service4 --env INSTANCE_NAME=4 --env TLS_ENABLED=true --env TLS_CERT_BASE64="$TLS_CERT_BASE64_4" --env TLS_KEY_BASE64="$TLS_KEY_BASE64_4" --network kind-cilium "${APP_IMG}"

TLS_CERT_BASE64_5=$(cat ${script_dir}/tls-secure-backend2.crt | base64)
TLS_KEY_BASE64_5=$(cat ${script_dir}/tls-secure-backend2.key | base64)
docker run -d --name app5 --rm --env SERVICE_NAME=service5 --env INSTANCE_NAME=5 --env TLS_ENABLED=true --env TLS_CERT_BASE64="$TLS_CERT_BASE64_5" --env TLS_KEY_BASE64="$TLS_KEY_BASE64_5" --network kind-cilium "${APP_IMG}"

#
# Client
#

# BGP client (FRR)
LB_T1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' kind-control-plane)

docker run -d --restart=always --name frr --privileged -e "NEIGHBOR=${LB_T1_IP}" --network kind-cilium quay.io/isovalent-dev/lb-frr-client:v0.0.1

# Copy Backend TLS secrets to FRR client
docker cp ${script_dir}/tls-secure-backend.crt frr:/tmp/tls-secure-backend.crt
docker cp ${script_dir}/tls-secure-backend2.crt frr:/tmp/tls-secure-backend2.crt

#
# LB configuration
#

# BGP config for FRR BGP peer

kubectl apply -f "${script_dir}/manifests/lb-bgp-frr-config.yaml"

BGP_FRR_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' frr)

kubectl patch bgpp ilb-test --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/virtualRouters/0/neighbors/0/peerAddress\", \"value\":\"${BGP_FRR_IP}/32\"}]"

# LB TLS secret for LB service
kubectl -n default delete secret test-secure 2>/dev/null || true
kubectl -n default delete secret test-secure80 2>/dev/null || true
kubectl -n default delete secret test-secure-http2 2>/dev/null || true

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure.key" -out "${script_dir}/tls-secure.crt" -subj "/CN=secure.acme.io"
kubectl -n default create secret tls test-secure --key="${script_dir}/tls-secure.key" --cert="${script_dir}/tls-secure.crt"
docker cp ${script_dir}/tls-secure.crt frr:/tmp/tls-secure.crt

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure80.key" -out "${script_dir}/tls-secure80.crt" -subj "/CN=secure-80.acme.io"
kubectl -n default create secret tls test-secure80 --key="${script_dir}/tls-secure80.key" --cert="${script_dir}/tls-secure80.crt"
docker cp ${script_dir}/tls-secure80.crt frr:/tmp/tls-secure80.crt

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-http2.key" -out "${script_dir}/tls-secure-http2.crt" -subj "/CN=secure-http2.acme.io"
kubectl -n default create secret tls test-secure-http2 --key="${script_dir}/tls-secure-http2.key" --cert="${script_dir}/tls-secure-http2.crt"
docker cp ${script_dir}/tls-secure-http2.crt frr:/tmp/tls-secure-http2.crt
