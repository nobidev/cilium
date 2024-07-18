#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.
set -x

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -n "Waiting until VIPs have been assigned "
while :; do
  VIP_LB1=$(kubectl -n default get lbvip lb-1   -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB2=$(kubectl -n default get lbvip lb-2-3 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB3=$(kubectl -n default get lbvip lb-2-3 -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB4=$(kubectl -n default get lbvip lb-4   -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB5=$(kubectl -n default get lbvip lb-5   -ojson | jq -r '.status.addresses.ipv4')
  VIP_LB6=$(kubectl -n default get lbvip lb-6   -ojson | jq -r '.status.addresses.ipv4')

  if [ "${VIP_LB1}" != "" ] && [ "${VIP_LB2}" != "" ] && [ "${VIP_LB3}" != "" ] && [ "${VIP_LB4}" != "" ] && [ "${VIP_LB5}" != "" ] && [ "${VIP_LB6}" != "" ]; then
    break
  fi

  echo -n "."
  sleep 1
done
echo ""

echo "Calling VIPs (might take some time until everything is up & running)"

docker exec frr bash -c "echo -n 'HTTPS    frontend1: ' && curl -s --cacert /tmp/tls-secure.crt --resolve secure.acme.io:443:${VIP_LB1} https://secure.acme.io:443/"
docker exec frr bash -c "echo -n 'HTTP     frontend2: ' && curl -s --resolve insecure.acme.io:80:${VIP_LB2} http://insecure.acme.io:80/api/foo-insecure"
docker exec frr bash -c "echo -n 'HTTP     frontend3: ' && curl -s http://${VIP_LB3}:81/"
docker exec frr bash -c "echo -n 'HTTP     frontend4: ' && curl -s --resolve mixed.acme.io:80:${VIP_LB4} http://mixed.acme.io:80/"
docker exec frr bash -c "echo -n 'HTTPS    frontend5: ' && curl -s --cacert /tmp/tls-secure80.crt --resolve secure-80.acme.io:80:${VIP_LB5} https://secure-80.acme.io:80/"
docker exec frr bash -c "echo -n 'TLS PT 1 frontend6: ' && curl -s --cacert /tmp/tls-secure-backend.crt --resolve passthrough.acme.io:80:${VIP_LB6} https://passthrough.acme.io:80/"
docker exec frr bash -c "echo -n 'TLS PT 2 frontend6: ' && curl -s --cacert /tmp/tls-secure-backend2.crt --resolve passthrough-2.acme.io:80:${VIP_LB6} https://passthrough-2.acme.io:80/"
