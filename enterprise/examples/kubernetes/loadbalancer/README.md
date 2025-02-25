# Isovalent LoadBalancer

## Install Isovalent LoadBalancer on a local Kind cluster

The next set of commands will install ILB with the default configuration and Prometheus + Perses as observability stack.

```sh
make kind-loadbalancer && \
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml && \
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/enterprise-kind-loadbalancer-dev.yaml make kind-install-cilium-fast && \
make kind-image-enterprise-fast && \
./enterprise/examples/kubernetes/loadbalancer/lb_configure.sh && \
./enterprise/examples/kubernetes/loadbalancer/deploy_perses.sh
```

Alternatively, to deploy the Grafana dashboards visualisation, replace the last line above with:

```sh
./enterprise/examples/kubernetes/loadbalancer/deploy_grafana.sh
```

Recompiling and deploying Cilium/ILB with the local changes run:

```sh
make kind-image-enterprise-fast
```

## Deploy & Test LoadBalancer example

```sh
./enterprise/examples/kubernetes/loadbalancer/example_install.sh && \
./enterprise/examples/kubernetes/loadbalancer/example_test.sh
```

## Observability

Prometheus is deployed to the ILB cluster for gathering and exposing the various cluster, ILB and operations metrics.

The `source of truth` dashboards for ILB will be the Grafana dashboards under `enterprise/dashboards/loadbalancer/grafana`. Yet to deploy them in production we're using Perses.

The conversion between Grafana json and Perses yaml is done with:

```sh
make sync-grafana-to-perses
```

To access the Perses UI at http://localhost:8080 execute the port-forwarding as follows:

```sh
   kubectl port-forward -n monitoring svc/perses 8080:8080
```

### Grafana (alternative)
To expose the Grafana dashboard:

```sh
kubectl -n monitoring port-forward deployment/prometheus-grafana 3000:3000
```

For more details and instructions see <https://github.com/isovalent/isovalent-loadbalancer-images/blob/main/README.md#observability>

## Delete LoadBalancer Kind Cluster & example Docker Containers

```sh
DELETE_CONTAINERS=true make kind-down
```
