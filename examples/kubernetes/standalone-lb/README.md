# Standalone Loadbalancer

## Create Kind cluster for local development

```
make kind-standalonelb
```

## Install Cilium

```
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-standalone-lb.yaml make kind-debug
```

## Configure Cilium as Standalone LB

Wait until Cilium Operator created CRDs in the Cluster (especially the `CiliumNodeConfig`)

```
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

## Cleanup

```
./examples/kubernetes/standalone-lb/cleanup_example.sh
```

## Delete Kind Cluster

```
make kind-down
```
