#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test HealthCheck backends
docker rm -f app1 2>/dev/null
docker rm -f app2 2>/dev/null
docker rm -f app3 2>/dev/null

docker run -d --name app1 --rm --env SERVICE_NAME=service1 --env INSTANCE_NAME=1 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1
docker run -d --name app2 --rm --env SERVICE_NAME=service2 --env INSTANCE_NAME=2 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1
docker run -d --name app3 --rm --env SERVICE_NAME=service3 --env INSTANCE_NAME=3 --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.1

# FRR client

docker rm -f frr 2>/dev/null
rm -rf ${script_dir}/frr/config

LB_T1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' kind-control-plane)

mkdir -p ${script_dir}/frr/config/etc/frr/config

cat ${script_dir}/frr/templates/frr-vtysh.conf | tee ${script_dir}/frr/config/etc/frr/vtysh.conf
cat ${script_dir}/frr/templates/frr-daemons | tee ${script_dir}/frr/config/etc/frr/daemons
sed -E "s/neighbor\s\S+\s/neighbor ${LB_T1_IP} /" ${script_dir}/frr/templates/frr.conf | tee ${script_dir}/frr/config/etc/frr/frr.conf

docker run -d --privileged --restart=always -v ${script_dir}/frr/config/etc/frr:/etc/frr:ro --name frr --network kind-cilium quay.io/frrouting/frr:7.5.1
docker exec frr bash -c "apk update && apk add curl"

# LB IPAM

kubectl apply -f ${script_dir}/manifests/lb-pool.yml

# BGP setup

kubectl apply -f ${script_dir}/manifests/bgp-policy.yml

BGP_FRR_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' frr)

kubectl patch bgpp frr --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/virtualRouters/0/neighbors/0/peerAddress\", \"value\":\"${BGP_FRR_IP}/32\"}]"

# Example
kubectl -n default delete secret test 2>/dev/null || true

openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${script_dir}/tls.key -out ${script_dir}/tls.crt -subj "/CN=foo.acme.io"
kubectl -n default create secret tls test --key="${script_dir}/tls.key" --cert="${script_dir}/tls.crt"
docker cp ${script_dir}/tls.crt frr:/tmp/tls.crt

kubectl apply -f ${script_dir}/manifests/loadbalancer.yml

BACKEND1_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app1)
BACKEND2_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app2)
BACKEND3_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app3)

kubectl patch lbbackend lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackend lb-1 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND2_IP}\"}]"

kubectl patch lbbackend lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND1_IP}\"}]"
kubectl patch lbbackend lb-2 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"

kubectl patch lbbackend lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/0/ip\", \"value\":\"${BACKEND2_IP}\"}]"
kubectl patch lbbackend lb-3 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/addresses/1/ip\", \"value\":\"${BACKEND3_IP}\"}]"
