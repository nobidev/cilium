# Isovalent LoadBalancer

## Install Isovalent LoadBalancer on a local Kind cluster

```sh
make kind-loadbalancer && \
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-loadbalancer.yaml make kind-debug && \
./examples/kubernetes/loadbalancer/lb_configure.sh
```

## Deploy & Test LoadBalancer example

```sh
./examples/kubernetes/loadbalancer/example_install.sh && \
./examples/kubernetes/loadbalancer/example_test.sh
```

## Delete LoadBalancer Kind Cluster & example Docker Containers

```sh
DELETE_CONTAINERS=true make kind-down
```
