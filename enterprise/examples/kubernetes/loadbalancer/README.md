# Isovalent LoadBalancer

## Install Isovalent LoadBalancer on a local Kind cluster

```sh
make kind-loadbalancer && \
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml && \
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/enterprise-kind-loadbalancer.yaml make kind-install-cilium-fast && \
make kind-image-enterprise-fast && \
./enterprise/examples/kubernetes/loadbalancer/lb_configure.sh && \
./enterprise/examples/kubernetes/loadbalancer/deploy_prometheus.sh
```

to recompile and deploy Cilium with the local changes:

```sh
make kind-image-enterprise-fast
```

## Deploy & Test LoadBalancer example

```sh
./enterprise/examples/kubernetes/loadbalancer/example_install.sh && \
./enterprise/examples/kubernetes/loadbalancer/example_test.sh
```

## Observability

Prometheus and Grafana are deployed to the ILB cluster for observability.

To expose the Grafana dashboard:

```sh
kubectl -n monitoring port-forward deployment/prometheus-grafana 3000:3000
```

For more details and instructions see <https://github.com/isovalent/isovalent-loadbalancer-images/blob/main/README.md#observability>

## Delete LoadBalancer Kind Cluster & example Docker Containers

```sh
DELETE_CONTAINERS=true make kind-down
```
