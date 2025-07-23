FQDN-Proxy ("cilium-dnsproxy")
============================

Overview
--------

This codebase is the FQDN-Proxy code from the cilium codebase
modularized as its own program, meant to run as its own deployment (daemonset).
It deployed via a separate Helm chart, so the upgade lifecycle is distinct from Cilium.

Normally, Cilium runs a DNS proxy server that intercepts DNS packets so that it can
look up IP addresses to enforce L7 policies that are based on FQDN rules.
When Cilium goes down this causes all pod-based DNS requests on its node to fail.

When FQDN-Proxy is deployed Cilium still runs its own DNS proxy server, but
the DNS requests are now routed to the FQDN-Proxy K8s Service which will continue
to service DNS requests even if Cilium is down. The FQDN-Proxy deployment
is a Daemonset (that is run on each node). This ensures that DNS
requests are served by an HA service.

While the agent is down, it caches all DNS requests so that policy may be updated
once the agent returns.

Agent - Proxy API
-----------------

The proxy needs to know all endpoints and their L7 DNS rules. This is so it can enforce
any L7 DNS policies, e.g. "only allow queries to *.example.com".

The proxy must also forward all DNS responses to the agent for policy and observability purposes.

The agent exposes a gRPC server on a socket file. The proxy connects to this and forwards requests.

Additionally, the proxy must get the L7 rules. The mechanism has evolved over time:

Current
-------

The proxy calls gRPC method SubscribeFQDNRules(). The agent streams all known and newly-learned endpoint
configurations. If the agent does not support this method, the proxy falls back to old behavior.

Pre-1.18
--------

The proxy first calls gRPC method GetRules(), which gives it a list of "restored fqdn rules". The distinction
is somewhat arcane, but restored rules are intended only for temporary use.

The proxy also exposes its own gRPC server. When the agent learns of a new endpoint configuration,
it calls the proxy's `UpdateAllowed()` method. When the agent first detects that a proxy has newly
started, it calls `UpdateAllowed()` for all known existing endpoints.



FQDN-HA Offline
---------------

When enabled, the proxy supports a mode where, when the agent is down, it writes directly to the BPF
IPCache. This will determine the identity for a given name and, if possible, write the identity
for that IP directly to the ipcache.

This is safe-to-do because the agent always creates a new BPF IPCache on restart. Once the agent
goes down, only the FQDN proxy will be writing to the old, outgoing IPCache. As the agent starts
up and endpoints are regenerated, they will switch to the new ipcache map. Once all endpoints
are regenerated, the proxy can drop its reference to the outgoing map.

## Handback

Once the proxy detects the agent is down, it queues the calls to `NotifyOnDNSMsg()` and writes
the newly-learned IPs to the BPF IPCache. Once the agent comes back up, there is a somewhat complicated
handback procedure.

1. Before the agent can proceed with regeneration, the notification queue must be empty.
   This is because the queue may contain newly-learned IPs. Those IPs have been written in to
   the "old" IPCache, but not the new one. Thus, they must also first be programmed in the new one.
2. The agent must not listen on the DNS proxy port until all endpoints have been regenerated. This
   is because all un-regenerated endpoints are still referencing the old IPCache. Only the ha-proxy
   can write to this. So, by delaying opening the port, all newly-learned IPs go to both IPCache maps.
   If the agent opened the port immediately, then a DNS message may be served by the agent, which cannot
   write to the outgoing IPCache, leading to a drop.
3. Once the agent has regenerated all endpoints, the proxy stops writing to the IPCache and reloads
   its BPF map.


How to Publish a New Version
----------------------------

### Ensure that the semantic version is up to date in the repository

The following files contain references to the semantic version of the codebase and should
be up to date before the image or helm chart is published:

- ./installation/Chart.yaml (run `make -C installation update-chart` to update it based on the `VERSION` file in the root directory of the repository)
- ./installation/README.md (run `./installation/test.sh` to generate this file).

### Run Compatibility Tests

In order to run the compatibility tests you must have kind, helm, kubectl, and cilium-cli installed.

Run the compatibility tests within the `scripts` directory. The first argument to the script is
a semicolon delimited list of FQDN-Proxy versions to test (in ascending order). The second argument
is a semicolon delimited list of Cilium versions to test (in ascending order). For example:

```bash
cd scripts
# The following line will test FQDN-Proxy versions "1.12.8-1.13.1" against
# Cilium versions "1.12.6-1.12.8"
./compat-test.sh "1.12.8;1.13.0;1.13.1" "1.12.6;1.12.7;1.12.8"
```

In the example above `compat-test.sh` will test FQDN-Proxy version 1.13.1 with Cilium
version 1.12.6, then upgrade Cilium to 1.12.7, then 1.12.8. Finally, it will test
Cilium version 1.12.8 with FQDN-Proxy version 1.12.8, then upgrade FQDN-Proxy to 1.13.0,
then 1.13.1.

After the script runs it will generate a list of potential upgrade problems. Note that the 
method of testing high availability for FQDN-Proxy involves bringing the Cilium damonset "down"
in a clumsy way and can lead to false negative results. Failures should be individually
run to verify them. Making this test more robust is being tracked by [this issue](https://github.com/isovalent/cilium-cli-ci/issues/6).

Once you have obtained compatibility results you can update the compatibility matrix in
this readme as well as the [Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/blob/master/docs/operations-guide/features/dnsproxy-ha/index.rst#versions-compatibility).

### Publish release notes

After releasing a new version of FQDN-Proxy, create a new page with the
customer-facing release notes of the new release in
in the [Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/tree/main/docs/operations-guide/releases/release-notes)
repo.

### Bump FQDN-Proxy version in Cilium Enterprise

After releasing a new version of FQDN-Proxy, update the FQDN-Proxy version in
the [isovant/cilium](https://github.com/isovalent/cilium/)
CI workflows and the Atlantis plugin (for v1.14 and older).

Compatibility Matrix with Cilium
--------------------------------

Please refer to the docs for the [Compatibility Matrix](https://docs.isovalent.com/operations-guide/releases/version-compatibility.html)

Backporting FQDN-Proxy Bug Fixes
--------------------------------
In the event that FQDN-Proxy needs a backported bug fix then new patch releases of FQDN-Proxy will be released
and the version should be documented in the Compatibility Matrix 
in this README and [the Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/blob/master/docs/operations-guide/features/dnsproxy-ha/index.rst#versions-compatibility).
Though we have not done this yet, we will also document the Cilium
library version overlap (so as to extend the Compatibility matrix) in FQDN-Proxy patch releases.

Hotfix Process
--------------
To create a hotfix image follow these instructions:

1. Make sure that your hotfix has been reviewed and tested (preferably in a PR).
2. Once your hotfix has been tested and approved create a new
   branch in this repository with the naming pattern
   `hf/<base branch>/<base tag>-<GH issue number>`, for example
   `hf/v1.13/v1.13-255`. **DO NOT** mention the customer's name
   in the hotfix branch. **DO NOT** create a new pull request.
   The hotfix workflow will be able to publish the image from the
   branch.
3. Wait for the hotfix image to be published.
4. Verify that the image is published at `quay.io/isovalent/cilium-dnsproxy:<base-tag>-<GH issue number>`
