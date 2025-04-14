#!/usr/bin/env bash

set -eu -o pipefail

EXTERNAL_TARGET="${1:-cilium.io}"
EXTERNAL_OTHER_TARGET="${2:-google.com}"

kubectl exec -n cilium-test-1 deploy/client -- nslookup $EXTERNAL_TARGET
kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 $EXTERNAL_TARGET

kubectl exec -n cilium-test-1 deploy/client -- nslookup $EXTERNAL_OTHER_TARGET

if kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 $EXTERNAL_OTHER_TARGET ; then
	echo "$EXTERNAL_OTHER_TARGET reached despite being blocked by fqdn policy"
	exit 1
fi
