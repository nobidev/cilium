# Isovalent LoadBalancer

## Create Kind cluster for local development

```
make kind-loadbalancer
```

## Install Cilium as LoadBalancer

```
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-loadbalancer.yaml make kind-debug && \
./examples/kubernetes/loadbalancer/configure_loadbalancer.sh
```

## Deploy LB scenario

```
./examples/kubernetes/loadbalancer/install_example.sh
```

## Test LB scenario

```
./examples/kubernetes/loadbalancer/test_example.sh
```

## Delete Kind Cluster & Docker Containers

```
DELETE_CONTAINERS=true make kind-down
```
