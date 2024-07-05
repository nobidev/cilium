#!/bin/bash

# Usage
#
# ./control.sh [t2-lb|backend] [<cilium-node-name>|<backend-container-name>] [healthcheck|response] [ok|fail]
#
# Change healthcheck state for a backend container
# ./control.sh backend app1 healthcheck fail
#
# Change response state for a backend container
# ./control.sh backend app1 response fail
#
# Change healthcheck state for a T2 loadbalancer instance
# ./control.sh t2-lb cilium-worker2 healthcheck fail

set -e

if [ -z ${1+x} ]; then
	echo "no instance type set [t2-lb|backend]"
	exit 1
fi

if [ -z ${2+x} ]; then
	echo "no instance name set [<cilium-node-name>|<backend-container-name>]"
	exit 1
fi

if [ -z ${3+x} ]; then
	echo "no type set [healthcheck|response]"
	exit 1
fi

if [ -z ${4+x} ]; then
	echo "no status set [ok|fail]"
	exit 1
fi

if [ "$1" = "backend" ]; then
	docker exec "$2" curl -s -X POST "http://localhost:8080/control/$3/$4"

elif [ "$1" = "t2-lb" ]; then
	NODE_IP=$(kubectl get nodes "$2" -oyaml | yq '.status.addresses[] | select(.type == "InternalIP").address | select(. == "*.*.*.*")')

	if [ "$3" = "response" ]; then
		echo "controlling response type currently not possible for t2-lb"
		exit 1
	fi

	curl -X POST "http://$NODE_IP:10000/$3/$4"
fi
