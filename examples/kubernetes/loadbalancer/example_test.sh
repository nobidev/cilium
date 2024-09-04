#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.
set -x

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -n "Waiting until VIPs have been assigned "
while :; do
  VIP_LB1=$(kubectl -n default get lbvip lb-1 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB2=$(kubectl -n default get lbvip lb-2-3 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB3=$(kubectl -n default get lbvip lb-2-3 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB4=$(kubectl -n default get lbvip lb-4 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB5=$(kubectl -n default get lbvip lb-5 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB6=$(kubectl -n default get lbvip lb-6 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB7=$(kubectl -n default get lbvip lb-7 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB8=$(kubectl -n default get lbvip lb-8 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB9=$(kubectl -n default get lbvip lb-9 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB10=$(kubectl -n default get lbvip lb-10 -ojson | jq -r '.status.addresses.ipv4')

  if [ "${VIP_LB1}" != "" ] &&
    [ "${VIP_LB2}" != "" ] &&
    [ "${VIP_LB3}" != "" ] &&
    [ "${VIP_LB4}" != "" ] &&
    [ "${VIP_LB5}" != "" ] &&
    [ "${VIP_LB6}" != "" ] &&
    [ "${VIP_LB7}" != "" ] &&
    [ "${VIP_LB8}" != "" ] &&
    [ "${VIP_LB9}" != "" ] &&
    [ "${VIP_LB10}" != "" ]; then
    break
  fi

  echo -n "."
  sleep 1
done
echo ""

echo -n "Waiting until BFD sessions are established "
until [ $(docker exec -it frr vtysh -c "show bfd peers json" | jq -r '.[].status=="up" // false') != *"false"* ]; do
  echo -n "."
  sleep 1
done
echo ""

echo -n "Waiting until BGP sessions are established "
until [ $(docker exec -it frr vtysh -c "show bgp summary json" | jq -r '.ipv4Unicast.peers[].state == "Established" // false') != *"false"* ]; do
  echo -n "."
  sleep 1
done
echo ""

function route_exists() {
  docker exec -it frr vtysh -c "show ip route json" |
    jq --arg PREFIX "$1/32" -r '.[$PREFIX] // [] | any(.protocol=="bgp" and .installed==true)'
}

echo -n "Waiting until the routes are installed "
until [ $(route_exists $VIP_LB1) == "true" ] &&
  [ $(route_exists $VIP_LB2) == "true" ] &&
  [ $(route_exists $VIP_LB3) == "true" ] &&
  [ $(route_exists $VIP_LB4) == "true" ] &&
  [ $(route_exists $VIP_LB5) == "true" ] &&
  [ $(route_exists $VIP_LB6) == "true" ] &&
  [ $(route_exists $VIP_LB7) == "true" ] &&
  [ $(route_exists $VIP_LB8) == "true" ] &&
  [ $(route_exists $VIP_LB9) == "true" ] &&
  [ $(route_exists $VIP_LB10) == "true" ]; do
  echo -n "."
  sleep 1
done
echo ""

echo "Calling VIPs (might take some time until everything is up & running)"

docker exec frr bash -c "echo -n 'HTTPS                 service1: ' && curl -s --fail --cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:${VIP_LB1} https://secure.acme.io:443/"
docker exec frr bash -c "echo -n 'HTTP                  service2: ' && curl -s --fail --resolve insecure.acme.io:80:${VIP_LB2} http://insecure.acme.io:80/api/foo-insecure"
docker exec frr bash -c "echo -n 'HTTP                  service3: ' && curl -s --fail http://${VIP_LB3}:81/"
docker exec frr bash -c "echo -n 'HTTP                  service4: ' && curl -s --fail --resolve mixed.acme.io:80:${VIP_LB4} http://mixed.acme.io:80/"
docker exec frr bash -c "echo -n 'HTTPS                 service5: ' && curl -s --fail -tlsv1.2 --cert /tmp/client.crt --key /tmp/client.key --cacert /tmp/tls-secure80.crt --resolve secure-80.acme.io:80:${VIP_LB5} https://secure-80.acme.io:80/"
docker exec frr bash -c "echo -n 'TLS PT 1              service6: ' && curl -s --fail --cacert /tmp/tls-secure-backend.crt --resolve passthrough.acme.io:80:${VIP_LB6} https://passthrough.acme.io:80/"
docker exec frr bash -c "echo -n 'TLS PT 2              service6: ' && curl -s --fail --cacert /tmp/tls-secure-backend2.crt --resolve passthrough-2.acme.io:80:${VIP_LB6} https://passthrough-2.acme.io:80/"
docker exec frr bash -c "echo -n 'HTTP H2               service4: ' && httpVersion=\$(curl -s --fail --http2-prior-knowledge -o/dev/null -w '%{http_version}' --resolve mixed.acme.io:80:${VIP_LB4} http://mixed.acme.io:80/) && echo Version \$httpVersion && if [ \$httpVersion != '2' ]; then exit 1; fi"
docker exec frr bash -c "echo -n 'HTTPS H2              service7: ' && httpVersion=\$(curl -s --fail -o/dev/null -w '%{http_version}' --cacert /tmp/tls-secure-http2.crt --resolve secure-http2.acme.io:443:${VIP_LB7} https://secure-http2.acme.io:443/) && echo Version \$httpVersion && if [ \$httpVersion != '2' ]; then exit 1; fi"
docker exec frr bash -c "echo -n 'HTTPS H2 UNDERSCORE   service1: ' && errMsg=\$(curl -s --http2 --fail --cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:${VIP_LB1} -H \"X_INVALID: foo\" -w '%{errormsg}' https://secure.acme.io:443/) || echo Error Message: \$errMsg | grep INTERNAL_ERROR"
docker exec frr bash -c "echo -n 'HTTP  UNDERSCORE      service2: ' && httpCode=\$(curl -s --fail --resolve insecure.acme.io:80:${VIP_LB2} -H \"X_INVALID: foo\" -w '%{http_code}' http://insecure.acme.io:80/api/foo-insecure) || echo Code \$httpCode && if [ \$httpCode != '400' ]; then exit 1; fi"
docker exec frr bash -c "echo -n 'HTTPS H2              service7: ' && httpVersion=\$(curl -s --fail -o/dev/null -w '%{http_version}' --cacert /tmp/tls-secure-http2.crt --resolve secure-http2.acme.io:443:${VIP_LB7} https://secure-http2.acme.io:443/) && echo Version \$httpVersion && if [ \$httpVersion != '2' ]; then exit 1; fi"
docker exec frr bash -c "echo -n 'HTTPS RE              service8: ' && curl -s --fail --cacert /tmp/tls-secure-backend3.crt --resolve secure-backend.acme.io:443:${VIP_LB8} https://secure-backend.acme.io:443/"
docker exec frr bash -c "echo -n 'TLS Proxy (TLS BE)    service10: ' && curl -s --fail --cacert /tmp/tls-secure-backend3.crt --resolve secure-backend.acme.io:10443:${VIP_LB10} https://secure-backend.acme.io:10443/api/foo"
docker exec frr bash -c "echo -n 'TLS Proxy (TCP BE)    service11: ' && curl -s --fail --cacert /tmp/tls-secure.crt --resolve secure.acme.io:10080:${VIP_LB10} https://secure.acme.io:10080/api/foo"

echo "Making lb-9 unhealthy"

docker kill app7

echo "Waiting for the BGP route to be withdrawn"

until [ $(route_exists $VIP_LB9) == "false" ]; do
  echo -n "."
  sleep 1
done

echo "Making lb-9 healthy again"

docker run -d --name app7 --rm --env SERVICE_NAME=service7 --env INSTANCE_NAME=7 --env H2C_ENABLED=true --network kind-cilium quay.io/isovalent-dev/lb-healthcheck-app:v0.0.4
BACKEND7_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' app7)
kubectl patch lbbackendpool lb-9 --type='json' -p="[{\"op\": \"replace\", \"path\": \"/spec/backends/0/ip\", \"value\":\"${BACKEND7_IP}\"}]"

echo "Waiting for the BGP route to be installed"

until [ $(route_exists $VIP_LB9) == "true" ]; do
  echo -n "."
  sleep 1
done
