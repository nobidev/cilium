#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.
set -x

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${script_dir}/common.sh"

#
# Backends
#

# Backend TLS Secret (for testing TLS passthrough - is mounted and used by test health check backend)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-backend.key" -out "${script_dir}/tls-secure-backend.crt" -subj "/CN=passthrough.acme.io"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-backend2.key" -out "${script_dir}/tls-secure-backend2.crt" -subj "/CN=passthrough-2.acme.io"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-backend3.key" -out "${script_dir}/tls-secure-backend3.crt" -subj "/CN=secure-backend.acme.io"

# Deploy Test health check backends
docker rm -f app1 2>/dev/null
docker rm -f app2 2>/dev/null
docker rm -f app3 2>/dev/null
docker rm -f app4 2>/dev/null
docker rm -f app5 2>/dev/null
docker rm -f app6 2>/dev/null

docker run -d --name app1 --rm --env SERVICE_NAME=service1 --env INSTANCE_NAME=1 --env H2C_ENABLED=true --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10
docker run -d --name app2 --rm --env SERVICE_NAME=service2 --env INSTANCE_NAME=2 --env H2C_ENABLED=true --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10
docker run -d --name app3 --rm --env SERVICE_NAME=service3 --env INSTANCE_NAME=3 --env H2C_ENABLED=true --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10

TLS_CERT_BASE64_4=$(cat ${script_dir}/tls-secure-backend.crt | base64)
TLS_KEY_BASE64_4=$(cat ${script_dir}/tls-secure-backend.key | base64)
docker run -d --name app4 --rm --env SERVICE_NAME=service4 --env INSTANCE_NAME=4 --env TLS_ENABLED=true --env TLS_CERT_BASE64="$TLS_CERT_BASE64_4" --env TLS_KEY_BASE64="$TLS_KEY_BASE64_4" --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10

TLS_CERT_BASE64_5=$(cat ${script_dir}/tls-secure-backend2.crt | base64)
TLS_KEY_BASE64_5=$(cat ${script_dir}/tls-secure-backend2.key | base64)
docker run -d --name app5 --rm --env SERVICE_NAME=service5 --env INSTANCE_NAME=5 --env TLS_ENABLED=true --env TLS_CERT_BASE64="$TLS_CERT_BASE64_5" --env TLS_KEY_BASE64="$TLS_KEY_BASE64_5" --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10

TLS_CERT_BASE64_6=$(cat ${script_dir}/tls-secure-backend3.crt | base64)
TLS_KEY_BASE64_6=$(cat ${script_dir}/tls-secure-backend3.key | base64)
docker run -d --name app6 --rm --env SERVICE_NAME=service6 --env INSTANCE_NAME=6 --env TLS_ENABLED=true --env TLS_CERT_BASE64="$TLS_CERT_BASE64_6" --env TLS_KEY_BASE64="$TLS_KEY_BASE64_6" --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.10

#
# Client
#

# BGP client (FRR)
frrClients=("frr" "frr2")
for i in "${frrClients[@]}"; do
  docker rm -f ${i} 2>/dev/null
done

neighbors=""
t1NodeNames=$(kubectl get nodes -l service.cilium.io/node=t1 -oyaml | yq_run '.items[].metadata.name')
for i in $(echo $t1NodeNames); do
  LB_T1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${i}")
  if [[ "${neighbors}" != "" ]]; then
    neighbors="${neighbors};"
  fi
  neighbors="${neighbors}${LB_T1_IP}"
done

for i in "${frrClients[@]}"; do
  docker run -d --restart=always --name ${i} --privileged -e "NEIGHBORS=${neighbors}" --network kind-cilium quay.io/isovalent-dev/lb-frr-client:v0.0.3
done

# Copy Backend TLS secrets to FRR client
for i in "${frrClients[@]}"; do
  docker cp ${script_dir}/tls-secure-backend.crt ${i}:/tmp/tls-secure-backend.crt
  docker cp ${script_dir}/tls-secure-backend2.crt ${i}:/tmp/tls-secure-backend2.crt
  docker cp ${script_dir}/tls-secure-backend3.crt ${i}:/tmp/tls-secure-backend3.crt
done

#
# LB configuration
#

# BGP config for FRR BGP peer

kubectl apply -f "${script_dir}/example/lb-bfd-frr-config.yaml"

BGP_FRR_IPS=()
for i in "${frrClients[@]}"; do
  BGP_FRR_IPS+=($(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${i}))
done

cp "${script_dir}/example/lb-bgp-frr-config.yaml" "${script_dir}/example/lb-bgp-frr-config.yaml-tmp"

for i in "${BGP_FRR_IPS[@]}"; do
  yq_run -i "select(document_index == 0) .spec.bgpInstances[0].peers += {\"name\": \"peer-${i}\", \"peerASN\": 64512, \"peerAddress\": \"${i}\", \"peerConfigRef\": {\"name\": \"frr-peer\"}}" "${script_dir}/example/lb-bgp-frr-config.yaml-tmp"
done

kubectl apply -f "${script_dir}/example/lb-bgp-frr-config.yaml-tmp"
rm "${script_dir}/example/lb-bgp-frr-config.yaml-tmp"

# LB TLS secret for LB frontend
kubectl -n default delete secret test-secure 2>/dev/null || true
kubectl -n default delete secret test-secure80 2>/dev/null || true
kubectl -n default delete secret test-secure-http2 2>/dev/null || true
kubectl -n default delete secret test-secure-backend 2>/dev/null || true
kubectl -n default delete secret test-secure-client 2>/dev/null || true

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure.key" -out "${script_dir}/tls-secure.crt" -subj "/CN=secure.acme.io"
kubectl -n default create secret tls test-secure --key="${script_dir}/tls-secure.key" --cert="${script_dir}/tls-secure.crt"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure80.key" -out "${script_dir}/tls-secure80.crt" -subj "/CN=secure-80.acme.io"
kubectl -n default create secret tls test-secure80 --key="${script_dir}/tls-secure80.key" --cert="${script_dir}/tls-secure80.crt"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/tls-secure-http2.key" -out "${script_dir}/tls-secure-http2.crt" -subj "/CN=secure-http2.acme.io"
kubectl -n default create secret tls test-secure-http2 --key="${script_dir}/tls-secure-http2.key" --cert="${script_dir}/tls-secure-http2.crt"

kubectl -n default create secret tls test-secure-backend --key="${script_dir}/tls-secure-backend3.key" --cert="${script_dir}/tls-secure-backend3.crt"

# Client certificate (including CA)
openssl genrsa -out "${script_dir}/ca.key" 2048
openssl req -new -x509 -key "${script_dir}/ca.key" -out "${script_dir}/ca.crt" -subj "/CN=ca.acme.io"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${script_dir}/client.key" -out "${script_dir}/client.crt" -subj "/CN=client.acme.io" -addext "subjectAltName = DNS:client.acme.io" -CA "${script_dir}/ca.crt" -CAkey "${script_dir}/ca.key"
kubectl -n default create secret generic test-secure-client --from-file="${script_dir}/ca.crt"

for i in "${frrClients[@]}"; do
  docker cp ${script_dir}/tls-secure.crt ${i}:/tmp/tls-secure.crt
  docker cp ${script_dir}/tls-secure80.crt ${i}:/tmp/tls-secure80.crt
  docker cp ${script_dir}/tls-secure-http2.crt ${i}:/tmp/tls-secure-http2.crt
  docker cp ${script_dir}/tls-secure-backend3.crt ${i}:/tmp/tls-secure-backend3.crt
  docker cp ${script_dir}/client.crt ${i}:/tmp/client.crt
  docker cp ${script_dir}/client.key ${i}:/tmp/client.key
done

# LB vips, frontends, backends & ippools
kubectl apply -f "${script_dir}/example/lb-vips.yaml"
kubectl apply -f "${script_dir}/example/lb-services.yaml"
kubectl apply -f "${script_dir}/example/lb-backends.yaml"
kubectl apply -f "${script_dir}/example/lb-ippools.yaml"

BACKEND1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app1)
BACKEND2_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app2)
BACKEND3_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app3)
BACKEND4_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app4)
BACKEND5_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app5)
BACKEND6_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app6)

kubectl patch lbbackendpool lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackendpool lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/1/ip\", \"value\":\"${BACKEND2_IP}\"}]"

kubectl patch lbbackendpool lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackendpool lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackendpool lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackendpool lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackendpool lb-4 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackendpool lb-4 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackendpool lb-5 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackendpool lb-5 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackendpool lb-6 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND4_IP}\"}]"

kubectl patch lbbackendpool lb-7 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND5_IP}\"}]"

kubectl patch lbbackendpool lb-8 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND6_IP}\"}]"
