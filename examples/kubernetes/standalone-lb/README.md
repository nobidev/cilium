# Standalone Loadbalancer

## Create Kind cluster for local development

```
make kind-standalonelb
```

## Install Cilium as Standalone LB

```
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-standalone-lb.yaml make kind-debug && \
./examples/kubernetes/standalone-lb/configure_loadbalancer.sh
```

## Deploy LB scenario

```
./examples/kubernetes/standalone-lb/install_example.sh
```

## Test LB scenario

```
./examples/kubernetes/standalone-lb/test_example.sh
```

## Delete Kind Cluster

```
./examples/kubernetes/standalone-lb/cleanup_example.sh && \
make kind-down
```
