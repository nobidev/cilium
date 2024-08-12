# Cilium WebSocket tunneling Getting Started Guide

## Termination setup

To set up WebSocket termination in a k8s cluster:
- start example workload, below instructions for SSH daemon. Workloads can be anything reachable from the k8s cluster.
- for non-Cilium cluster, use the provided cilium-envoy image (A)
- for a Cilium cluster, use the provided CiliumEnvoyConfig CRD (B)

### Example workload setup

1. Start test endpoint for sshd

```
kubectl run --image=testcontainers/sshd:1.1.0 sshd -- sh -c 'echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && /usr/sbin/sshd -D'
```

2. Observe the IP of the sshd image

```
SSHD_IP=`kubectl get pod sshd -o json | jq -r '.status.podIP'`
echo ${SSHD_IP}
```

3. Test ssh session locally

> NOTE: Use password `root`

```
kubectl run -it --rm ssh-client --image=testcontainers/sshd:1.1.0  -- ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -l root ${SSHD_IP}
```

### A. Use the Cilium Envoy image for WebSocket termination in a non-Cilium cluster

1. Create TLS secret for WebSocket termination

> NOTE: The following works for domains managed by AWS Route53. You'll need to adapt this to your
> own server DNS name and your own secrets. `websocket.domain` is a placeholder here!

```
pipenv install certbot_dns_route53
pipenv shell

 EMAIL=<YOUR_EMAIL>@<YOUR_DOMAIN>
 certbot certonly --dns-route53 \
   -d '*.websocket.domain' \
   --email $EMAIL \
   --agree-tos --non-interactive \
   --logs-dir ./logs --config-dir ./config --work-dir ./work
 exit

kubectl create secret tls websocket-termination-server-certs \
  --key ./config/live/websocket.domain/privkey.pem \
  --cert ./config/live/websocket.domain/fullchain.pem
```

2. Create ConfigMap for Envoy configuration

```
kubectl create configmap websocket-termination-envoy-config --from-file=envoy.yaml=enterprise/examples/websocket/server/websocket-tunnel-termination-envoy-config.yaml
```

3. Deploy Envoy for WebSocket termination

> NOTE: Number of replicas is set to 1, edit as needed

```
kubectl apply -f enterprise/examples/websocket/server/envoy-websocket-termination.yaml
```

3. Observe Envoy WebSocket termination logs

```
# kubectl logs -l app=cilium-websocket-termination --tail=-1
```

### B. Using Cilium Envoy Config in a Cilium Cluster

> NOTE: Your Cilium cluster must be running in `strict` kube proxy replacement mode.

1. Create TLS secret for WebSocket termination in cilium-secrets namespace.

> NOTE: You'll need to adapt this to your own server DNS name and your own secrets.

```
<create TLS cert for *.cilium.rocks>

kubectl create --namespace cilium-secrets secret tls websocket-termination-server-certs \
  --key ./config/live/cilium.rocks/privkey.pem \
  --cert ./config/live/cilium.rocks/fullchain.pem
```

2. Deploy CiliumEnvoyConfig for WebSocket termination.

> NOTE: You'll need to adapt the Yaml for your secret's name!

```
kubectl apply -f enterprise/examples/websocket/server/cilium-websocket-termination.yaml
```

3. Observe L7 Hubble events

> NOTE: Refer to Hubble Getting Started Guide to install Hubble (use 'Ctrl-c' to exit)

```
hubble observe --type=l7 -f
```


## Client-side WebSocket encap setup

1. Create client cluster

> NOTE: This example uses Kind, but any k8s cluster capable of running Cilium 1.15-ce should work.

```
kind create cluster --config=enterprise/examples/websocket/client/kind-config.yaml
```

2a. Install Cilium Enterprise (Helm)

> NOTE: This install is for a single node cluster, remove `operator.replicas=1` option if this is a multi-node cluster.

```
helm install cilium isovalent/cilium --namespace kube-system --set dnsPolicy=ClusterFirstWithHostNet --set envoyConfig.enabled=true --set=debug.enabled=true --set=debug.verbose=envoy --set operator.replicas=1
```

2b. Install Cilium Enterprise (Cilium CLI)

> NOTE: This needs cilium-cli version 1.15.2 or later for helm mode, tested on 1.16.13.
> This install is for a single node cluster, remove `operator.replicas=1` option if this is a multi-node cluster.

```
cilium install --repository https://helm.isovalent.com --set dnsPolicy=ClusterFirstWithHostNet --set envoyConfig.enabled=true --set=debug.enabled=true --set=debug.verbose=envoy --set operator.replicas=1
```

Wait for Cilium install to complete:
```
cilium status --wait
```

3. Run connectivity test to verify installation

```
cilium connectivity test
```

4. Add Envoy WebSocket listener

> NOTE: This yaml contains the domain name `jarno.cilium.rocks` as the tunnel destination. Please edit to suit your setup.

```
kubectl apply -f enterprise/examples/websocket/client/websocket-encap.yaml
```

5. Add Cilium Network Policy redirecting SSH traffic to the WebSocket tunnel

```
kubectl apply -f enterprise/examples/websocket/client/ssh-to-websocket.yaml
```

This example policy applies to any pods in the `default` namespace with `run=ssh-client` label, and
allows all DNS requests to port 53, while all traffic to destination port 22 (ssh) is redirected to
the `cilium-websocket-encap` listener set up in step 4 above. No other traffic is allowed for pods
with `run=ssh-client` label. All other pods remain in the default-allow mode.

6. Run ssh from client cluster

> NOTE: Substitute IP or DNS name of the desired destination
> NOTE: Use password "root"

```
SSHD_IP=<IP of the desired workload>
kubectl run -it --rm ssh-client --image=testcontainers/sshd:1.1.0  -- ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -l root ${SSHD_IP}
```

7. Tunnel to any destination

Add Cilium Network Policy redirecting all external traffic from any pod to the WebSocket tunnel

```
kubectl apply -f enterprise/examples/websocket/client/external-https-to-websocket.yaml
```

This example policy applies to any pods in the `default` namespace, and allows all DNS requests to
port 53, while TCP to port 443 (https) is redirected to the `cilium-websocket-encap` listener set up
in step 4 above. Pods in all other namespaces remain in the default-allow mode.

Example command to fetch google home page via the tunnel:
```
kubectl run -it --rm curl --image=curlimages/curl:8.1.1 -- curl https://www.google.com
```

Right after the above command, observe the client side websocket logs to see what happened:
```
kubectl logs --timestamps -n kube-system -l k8s-app=cilium --tail=-1 | grep -C20 sec-websocket
```


## Client-side WebSocket encap setup with HTTP Proxy

1. Create client cluster

> NOTE: This example uses Kind, but any k8s cluster capable of running Cilium 1.15-ce should work.

```
kind create cluster --config=enterprise/examples/websocket/client/kind-config.yaml
```

2a. Install Cilium Enterprise (Helm)

> NOTE: This install is for a single node cluster, remove `operator.replicas=1` option if this is a multi-node cluster.

```
helm install cilium isovalent/cilium --namespace kube-system --set dnsPolicy=ClusterFirstWithHostNet --set envoyConfig.enabled=true --set=debug.enabled=true --set=debug.verbose=envoy --set operator.replicas=1
```

2b. Install Cilium Enterprise (Cilium CLI)

> NOTE: This needs cilium-cli version 1.15.2 or later for helm mode, tested on 1.16.13.
> This install is for a single node cluster, remove `operator.replicas=1` option if this is a multi-node cluster.

> NOTE: Cilium Enterprise 1.15.5 may fail to installed with `cilium install`

```
cilium install --repository https://helm.isovalent.com --set dnsPolicy=ClusterFirstWithHostNet --set envoyConfig.enabled=true --set=debug.enabled=true --set=debug.verbose=envoy --set operator.replicas=1
```

Wait for Cilium install to complete:
```
cilium status --wait
```

3. Run connectivity test to verify installation

```
cilium connectivity test
```

> NOTE: Make sure you do not have any CiliumNetworkPolicies (cnp), CiliumClusterwideNetworkPolicies
> (ccnp), CiliumEnvoyConfigs (cec), or CiliumClusterwideEnvoyConfigs (ccec) deployed before
> proceeding.

4. Deploy Squid proxy to your edge cluster

```
kubectl apply -f enterprise/examples/websocket/client/proxy-deployment.yaml
```
This proxy is configured with username "cilium" and password "secret".

5. Add Envoy WebSocket listener with HTTP proxy redirection

```
kubectl apply -f enterprise/examples/websocket/client/websocket-proxy-encap.yaml
```

This adds an additinal Envoy internal listener that tunnels traffic to
`http-proxy.default.svc.cluster.local:1080` using a HTTP CONNECT tunnel.

6. Add Envoy listener for HTTP proxy redirection without websocket

```
kubectl apply -f enterprise/examples/websocket/client/proxy-encap.yaml
```

This adds an Envoy listener that tunnels traffic to `http-proxy.default.svc.cluster.local:1080`
using a HTTP CONNECT tunnel without websocket encapsulation.

7. Add Cilium Network Policy redirecting all external HTTPS and SSH traffic to the WebSocket tunnel

```
kubectl apply -f enterprise/examples/websocket/client/default-to-websocket-proxy.yaml
```

This example policy applies to any pods in the `default` namespace with anything but
`app=http-proxy` label, and allows all DNS requests to port 53, while all traffic to destination
ports 22 (ssh) and 443 (https) are redirected to the `cilium-websocket-encap` listener set up in the
CiliumClusterwideEnvoyConfig `websocket-proxy-encap` (step 5 above). No other traffic is allowed for
pods without `app=http-proxy` label. Only the pods with `app=http-proxy` label remain in the
default-allow mode.

7. Run ssh from client cluster

> NOTE: Substitute IP or DNS name of the desired destination
> NOTE: Use password "root"

```
SSHD_IP=<IP of the desired workload>
kubectl run -it --rm ssh-client --image=testcontainers/sshd:1.1.0  -- ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -l root ${SSHD_IP}
```

You can launch `cilium monitor` in another terminal on your edge cluster to observe traffic to/from the HTTP proxy. Typically there is nothing to see if nothing is proxied through the HTTP proxy.

- obtain the cilium agent pod name `cilium-XXXXX` in the `kube-system` namespace via `kubectl get pods -A -o wide`

```
kubectl exec -it -n kube-system cilium-XXXXX -- cilium monitor --related-to `kubectl get cep -l app=http-proxy -o json | jq ".items[0].status.id"`
```

8. Tunnel to "*.google.com" directly via HTTP proxy

Add Cilium Network Policy redirecting all traffic to google.com from any pod to the HTTP proxy without websocket tunneling:

```
kubectl apply -f enterprise/examples/websocket/client/google-https-to-proxy.yaml
```

This example policy applies to any pods in the `default` namespace without the `app=http-proxy` label, and allows all DNS requests to
port 53, while DNS names with "*.google.com" pattern to port 443 (https) are redirected to the `http-proxy-encap` listener set up
in CiliumClusterwideEnvoyConfig `proxy-encap` (step 6 above). All other pods remain in the default-allow mode.

Example command to fetch google home page via the tunnel:
```
kubectl run -it --rm curl --image=curlimages/curl:8.1.1 -- curl https://www.google.com
```

Right after the above command, observe the client side HTTP CONNECT logs to see what happened:
```
kubectl logs --timestamps -n kube-system -l k8s-app=cilium --tail=-1 | grep -C20 -e CONNECT -e sec-websocket
```

