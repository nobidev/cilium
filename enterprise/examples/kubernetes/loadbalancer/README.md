# Isovalent LoadBalancer

## Install Isovalent LoadBalancer on a local Kind cluster

The next set of commands will install ILB with the default configuration and Prometheus + Grafana as the observability stack.

```sh
make kind-loadbalancer && \
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml && \
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/enterprise-kind-loadbalancer.yaml make kind-install-cilium-fast && \
make kind-image-enterprise-fast && \
./enterprise/examples/kubernetes/loadbalancer/configure_ilb_nodes.sh && \
./enterprise/examples/kubernetes/loadbalancer/deploy_grafana.sh
```

To setup the kind cluster for in-cluster mode where all nodes have T1 & T2 functionality configured,
just pass `in-cluster` as first argument to `configure_ilb_nodes.sh`.

```sh
./enterprise/examples/kubernetes/loadbalancer/configure_ilb_nodes.sh in-cluster
```

Alternatively, to deploy Perses as the visualization stack, replace the last line above with:

```sh
./enterprise/examples/kubernetes/loadbalancer/deploy_perses.sh
```

Recompiling and deploying Cilium/ILB with the local changes run:

```sh
make kind-image-enterprise-fast
```

## Test LoadBalancer

Compile `./cilium-cli`:

```sh
cd ./cilium-cli && make
./cilium version
```

Run some tests in:

* `multi-node` mode (deploys client and LB app containers in separate network namespaces):

```sh
DOCKER_API_VERSION=1.45 ./cilium lb test --run 'TestHTTP.*'
```

* `single-node` mode (deploys client and LB app containers on a single node in the same host network namespace):

```sh
docker run -d --name outside --env DOCKER_TLS_CERTDIR="" --privileged=true --network kind-cilium  docker:27.3.1-dind
ip=$(docker inspect '--format={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' outside)
DOCKER_API_VERSION=1.45 DOCKER_HOST="tcp://${ip}:2375" ./cilium lb test --run 'TestHTTP.*' --mode=single-node --single-node-ip=$ip
```

To avoid removal of test containers and services after a tests run, use `--cleanup=false`.

For the verbose/debug output, use: `--verbose`.

## Observability

Prometheus is deployed to the ILB cluster for gathering and exposing the various cluster, ILB and operations metrics.

The `source of truth` dashboards for ILB will be the Grafana dashboards under `enterprise/dashboards/loadbalancer/grafana`. Yet to deploy them in production we're using Perses.

The conversion between Grafana json and Perses yaml is done with:

```sh
make sync-grafana-to-perses
```

To access the Perses UI at <http://localhost:8080> execute the port-forwarding as follows:

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

## Deploying a test IPFIX collector

Note that a newer version of this manifest may be available

```
kubectl apply -f https://github.com/vmware/go-ipfix/releases/download/v0.12.0/ipfix-collector.yaml
```

## Gateway API

_Currently an alpha feature_.

You can use Gateway API to program the ILB. The following steps below is the fastest way to use Gateway API with ILB. The following steps will deploy an environment on a local Kind cluster. This setup is assuming you have the necessary BGP and IPPool setup.

1. Similar to above, create a Kind cluster 
```sh
make kind-loadbalancer && \
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml && \
./enterprise/examples/kubernetes/loadbalancer/configure_ilb_nodes.sh
```
2. Update the `contrib/testing/enterprise-kind-loadbalancer.yaml` in 2 locations to have the following:
```
enterprise:
  loadbalancer:
    enabled: true
    gatewayAPI: # this line 
      enabled: true # this line
...
```

3. Run the following
```
ADDITIONAL_KIND_VALUES_FILE=contrib/testing/enterprise-kind-loadbalancer.yaml make kind-install-cilium-fast
```

4. Install Gateway API CRDs
```
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/gateway.networking.k8s.io_gatewayclasses.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/gateway.networking.k8s.io_gateways.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/gateway.networking.k8s.io_httproutes.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/gateway.networking.k8s.io_referencegrants.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/standard/gateway.networking.k8s.io_grpcroutes.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v1.3.0/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml
```

5. Run the following
```
make kind-image-enterprise-fast 
```

6. Setup the Gateway Class by applying the following
```
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: ilbgateway 
spec:
  controllerName: io.isovalent/gateway-controller
  description: The default Isovalent LB GatewayClass
EOF
```

And check that it is ACCEPTED
```
kubectl get gatewayclass
// Should output the following
NAME         CONTROLLER                        ACCEPTED   AGE
ilbgateway   io.isovalent/gateway-controller   True       23m
```

7. You can now create other Gateway API resources to program your ILB. 
Note that there are some caveats with this alpha feature. 
- Only HTTPRoutes are supported for now
- Uses the `LBVIP` resource to provision an IP Address
- Resources reconciled by ILB CRDs and Gateway API CRDs clash if they have the same name. Avoid naming them the same to avoid this error.
