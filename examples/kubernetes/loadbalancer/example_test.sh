#!/usr/bin/env bash

set -e          # Exit if any command has a non-zero exit status
set -u          # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VIP_LB1=$(kubectl -n default get lbfe lb-1 -ojson | jq -r '.status.vip')
VIP_LB2=$(kubectl -n default get lbfe lb-2 -ojson | jq -r '.status.vip')
VIP_LB3=$(kubectl -n default get lbfe lb-3 -ojson | jq -r '.status.vip')

echo "Calling VIPs (might take some time until everything is up & running)"

docker exec frr bash -c "echo -n 'HTTP  T1: ' && curl -s http://${VIP_LB1}:80/"
docker exec frr bash -c "echo -n 'HTTP  T2: ' && curl -s http://${VIP_LB2}:80/"
docker exec frr bash -c "echo -n 'HTTP  T3: ' && curl -s http://${VIP_LB3}:81/"

docker exec frr bash -c "echo -n 'HTTPS T1: ' && curl -s --cacert /tmp/tls.crt --resolve foo.acme.io:80:${VIP_LB1} https://foo.acme.io:80/"
