#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#
# Backends
#

# Deploy Test health check backends
docker rm -f app1 2>/dev/null
docker rm -f app2 2>/dev/null
docker rm -f app3 2>/dev/null

docker run -d --name app1 --rm --env SERVICE_NAME=service1 --env INSTANCE_NAME=1 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1
docker run -d --name app2 --rm --env SERVICE_NAME=service2 --env INSTANCE_NAME=2 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1
docker run -d --name app3 --rm --env SERVICE_NAME=service3 --env INSTANCE_NAME=3 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1

#
# Client
#

# BGP client (FRR)
docker rm -f frr 2>/dev/null

LB_T1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' kind-control-plane)

docker run -d --restart=always --name frr --privileged -e NEIGHBOR=${LB_T1_IP} --network kind-cilium quay.io/isovalent-dev/lb-frr-client:v0.0.1

#
# LB configuration
#

# BGP config for FRR BGP peer

kubectl apply -f "${script_dir}/example/lb-bgp-frr-config.yaml"

BGP_FRR_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' frr)

kubectl patch bgpp frr --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/virtualRouters/0/neighbors/0/peerAddress\", \"value\":\"${BGP_FRR_IP}/32\"}]"

# LB TLS secret for LB frontend
kubectl -n default delete secret test-secure 2>/dev/null || true
kubectl -n default delete secret test-secure80 2>/dev/null || true

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure.key" -out "${script_dir}/tls-secure.crt" -subj "/CN=secure.acme.io"
kubectl -n default create secret tls test-secure --key="${script_dir}/tls-secure.key" --cert="${script_dir}/tls-secure.crt"
docker cp ${script_dir}/tls-secure.crt frr:/tmp/tls-secure.crt

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure80.key" -out "${script_dir}/tls-secure80.crt" -subj "/CN=secure-80.acme.io"
kubectl -n default create secret tls test-secure80 --key="${script_dir}/tls-secure80.key" --cert="${script_dir}/tls-secure80.crt"
docker cp ${script_dir}/tls-secure80.crt frr:/tmp/tls-secure80.crt

# LB frontends, backends & ippools
kubectl apply -f "${script_dir}/example/lb-frontends.yaml"
kubectl apply -f "${script_dir}/example/lb-backends.yaml"
kubectl apply -f "${script_dir}/example/lb-ippools.yaml"

BACKEND1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app1)
BACKEND2_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app2)
BACKEND3_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app3)

kubectl patch lbbackend lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackend lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND2_IP}\"}]"

kubectl patch lbbackend lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackend lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackend lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackend lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackend lb-4 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackend lb-4 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackend lb-5 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackend lb-5 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"
