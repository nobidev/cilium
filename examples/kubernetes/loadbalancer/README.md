# Isovalent LoadBalancer

## Install Isovalent LoadBalancer on a local Kind cluster

```sh
make kind-loadbalancer && \
make kind-ready && \
make kind-build-image-agent && \
make kind-build-image-operator && \
kind load docker-image localhost:5000/cilium/cilium-dev:local -n kind --nodes kind-control-plane,kind-worker && \
kind load docker-image localhost:5000/cilium/cilium-dev:local -n kind --nodes kind-worker2,kind-worker3,kind-worker4 && \
kind load docker-image localhost:5000/cilium/operator-generic:local -n kind --nodes kind-control-plane,kind-worker && \
kind load docker-image localhost:5000/cilium/operator-generic:local -n kind --nodes kind-worker2,kind-worker3,kind-worker4 && \
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml && \
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/kind-loadbalancer.yaml make kind-install-cilium && \
./examples/kubernetes/loadbalancer/lb_configure.sh && \
./examples/kubernetes/loadbalancer/deploy_prometheus.sh
```

## Deploy & Test LoadBalancer example

```sh
./examples/kubernetes/loadbalancer/example_install.sh && \
./examples/kubernetes/loadbalancer/example_test.sh
```
## Observability

Prometheus and Grafana are deployed to the ILB cluster for observability. For more details and instructions see https://github.com/isovalent/isovalent-loadbalancer-images/blob/main/README.md#observability

## Delete LoadBalancer Kind Cluster & example Docker Containers

```sh
DELETE_CONTAINERS=true make kind-down
```
