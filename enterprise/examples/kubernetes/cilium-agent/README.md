# Cilium Agent standalone run with Load Balancer state

The guide explains how to run the Cilium agent locally in standalone (non-K8S) mode and use the `cilium-dbg` tool to ineract with the agent.

## Build Cilium agent binary

```sh
cd daemon
go build .
```

## Build `cilium-dbg` binary

```sh
cd cilium-dbg
go build .
sudo mv cilium-dbg /usr/local/bin
```

## Prepare Load Balancer state file

You can use the file example below:

```yaml
services:
   - metadata:
       name: echo
       namespace: test
     spec:
       ports:
       - name: http
         port: 80
         protocol: TCP
         targetPort: 80
       type: LoadBalancer
     status:
       loadBalancer:
         ingress:
         - ip: 147.28.240.155

endpoints:
   - metadata:
       labels:
         name: echo
       name: echo-ep1
       namespace: test
     addressType: IPv4
     endpoints:
     - addresses:
       - 1.1.1.1
       conditions:
         ready: true
         serving: true
         terminating: false
     ports:
     - name: http
       port: 80
       protocol: TCP
```

Save the file snippet into `state.yaml`.

## Run Cilium agent

Use the following command to run the Cilium agent:

```sh
sudo ./daemon/daemon --enable-ipv4=true \
                     --bpf-lb-acceleration=disabled \
                     --devices=wlp9s0f0 \
                     --disable-envoy-version-check=true \
                     --enable-k8s=false \
                     --lb-state-file=<path to state.yaml file> \
                     --lb-state-file-interval=10ms \
                     --kube-proxy-replacement=true \
                     --routing-mode=native \
                     --enable-ipv4-masquerade=false \
                     --enable-ipv6-masquerade=false \
                     --bpf-lb-map-max=327680 \
                     --bpf-lb-mode-annotation=true \
                     --bpf-lb-dsr-dispatch=ipip
```

The Load Balancer state will be loaded from the state file and automatically reloaded in case of file modification.

## Interaction with Cilium agent

Use the `cilium-dbg` tool, for example:

```sh
sudo cilium-dbg service list
```
