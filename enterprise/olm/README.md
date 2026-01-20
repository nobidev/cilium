# CLife - Cilium Lifecycle Operator 

Pronunciation: sea life

CLife aims at managing the lifecycle of Cilium components from installation
to upgrade and removal.

## Description

CLife is a replacement of cilium-ee-olm that leads to an improved deployment experience on OpenShift and later on other platforms. It also aims at offering a lighter, less time consuming release process. The minimum viable product intends to set the foundations for advanced capabilities like: changes and upgrades readiness for a safer user experience, controlling out-of-band changes and environment aware auto-configuration.

## Getting Started

### Prerequisites

- go version v1.21.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on a cluster

**Create a kind cluster**

```sh
kind create cluster --name <your-cluster-name>
```

**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/clife:tag
```

> [!NOTE]
> This image oughts to be published in the personal registry you specified.
> It may be required to provide access rights to pull this image from the development cluster.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/clife:tag
```

> [!NOTE]
> If you encounter RBAC errors, you may need to grant yourself cluster-admin
> privileges or be logged in as admin.

**Create an instance of the custom resource:**

```sh
kubectl apply -k config/samples/
```

### To Uninstall

**Delete the custom resources from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs (CRDs) from the cluster:**

```sh
make uninstall
```

**Remove the controller from the cluster:**

```sh
make undeploy
```

## Manifests

Follow these steps to generate Cilium Lifecycle Operator manifests and to install it using these manifests.

1. Build the operator for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/clife:tag
```

> [!NOTE]
> The makefile target mentioned above generates an 'install.yaml'
> file in the dist directory. This file contains all the resources generated
> by Kustomize.

2. Use the generated manifests:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/olm/<tag or branch>/dist/install.yaml
```

## OLM

Generate the Operator Lifecycle Manager (OLM) bundle manifests with:

```sh
make bundle VERSION=xxx IMG=<some-registry>/clife:tag IMAGE_TAG_BASE=<some-registry>/clife
```
xxx is the Cilium version populated in the ClusterServiceVersion, e.g. 1.17.1

Create the bundle image with:
```sh
make bundle-build VERSION=xxx IMAGE_TAG_BASE=<some-registry>/clife
```

Push the bundle image to the registry with:

```sh
make bundle-push VERSION=xxx IMAGE_TAG_BASE=<some-registry>/clife
```

Metadata and configuration changes need to be applied to: `config/manifests/bases/clife.clusterserviceversion.yaml` and `bundle/metadata/annotations.yaml`. The ClusterServiceVersion in the bundle directory gets automatically updated.

Generate the manifests and populate an OLM catalog image with the follwing:
```sh
make catalog-dev-build VERSION="xxx" IMAGE_TAG_BASE=<some-registry>/clife CHANNEL="ccc"
make catalog-dev-push VERSION="xxx" IMAGE_TAG_BASE=<some-registry>/clife
```
It will also add the bundle with version xxx to the catalog channel ccc. If a catalog already exists at <some-registry>/clife-catalog the bundle will be added to it otherwise a new catalog will be generated.

To deploy Cilium on a kind cluster using OLM.

Install OLM:
```sh
operator-sdk olm install
```

Create a cilium namespace:
```sh
kubectl create ns cilium
```

Create an OperatorGroup:
```sh
cat <<EOF | kubectl create -f -
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: clife
  namespace: cilium
spec:
  upgradeStrategy: Default
status:
  namespaces:
  - ""
EOF
```

Create a CatalogSource:
```sh
cat <<EOF | kubectl create -f -
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: clife-catalog
  namespace: cilium
spec:
  sourceType: grpc
  image:  <some-registry>/clife-catalog:latest
EOF
```

Create a Subscription:
```sh
cat <<EOF | kubectl create -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/tetragon-operator.tetragon: ""
  name: cilium
  namespace: cilium
spec:
  name: clife
  source: clife-catalog
  sourceNamespace: cilium
  config:
    env:
EOF
```

Create a custom resource CiliumConfig with the desired configuration, e.g.:
```sh
kubectl apply -k config/samples/
```

## Contributing

> [!TIP]
> Run `make help` to get information on all `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

### Running the controller locally

For quicker feedback loop and easy debugging from IDEs during the development phase it is possible to run the controller locally.
Therefore the controller can be started direcly from an IDE or the command line by configuring a few environment variables and
passing a few parameters.

**Prerequisites:**
First, ensure the manifests folder exists by running:
```sh
make sync-helm-manifests
```

Environment variables:
- KUBECONFIG: The location of a kubeconfig file providing access to a development cluster, possibly a kind cluster.
- NAMESPACE: the namespace where the Cilium resources get created, e.g. "cilium".

Parameters:
- --helm-path: the location of the helm files, e.g. ./manifests
- --zap-log-level: the log level (logr). 4 or higher would give a higher level of details convenient for troubleshooting.

Hence the controller can be started from the command line with something similar to this:

```sh
KUBECONFIG=/tmp/kind.kubeconfig;NAMESPACE=cilium; ./bin/manager --helm-path "./manifests" --zap-log-level 6
```

The following configuration can be used in VS Code:

```json
{
    "name": "Debug CLife",
    "type": "go",
    "request": "launch",
    "mode": "debug",
    "program": "${fileDirname}",
    "env": {
        "KUBECONFIG": "/tmp/kind.kubeconfig",
        "NAMESPACE": "cilium"
    },
    "cwd": "${workspaceFolder}",
    "args": [
        "--helm-path",
        "${workspaceFolder}/manifests",
        "--zap-log-level",
        "6"
    ]
}
```

### Running end-to-end tests

Binaries for etcd and the API server need to be available for running end-to-end tests.
A make target has been created for the purpose. An environment variable may need to point to the installation location.

```sh
make envtest
./bin/setup-envtest use 1.31.0
/home/<user>/.local/share/kubebuilder-envtest/k8s/1.31.0-linux-amd64
# using the output from the previous command
export KUBEBUILDER_ASSETS="/home/<user>/.local/share/kubebuilder-envtest/k8s/1.31.0-linux-amd64/"
```

Afterwards the E2E tests can simply be run with

```sh
make test-e2e
```

Alternatively they can be run from VS Code by configuring settings.json

```json
{
    "go.testEnvVars": {
        "KUBEBUILDER_ASSETS": "/home/<user>/.local/share/kubebuilder-envtest/k8s/1.31.0-linux-amd64/"
    },
    "go.testTimeout": "120s"
}
```

### Running CI tests on OpenShift

CLife has been added to Cilium Continuous Integration infrastructure, for the main-ce branch at the time of writing. This means that:

- A workflow, [OLM Build CI](../../.github/workflows/enterprise-olm-build-ci.yaml), is triggered when changes are made to `enterprise/olm`. This workflow builds a new CLife container image and pushes it to quay.
- A final workflow, [Conformance OpenShift (ci-openshift)](../../.github/workflows/enterprise-conformance-openshift.yaml), gets also triggered on changes made to `enterprise/olm` and run CLI connectivity, CNI conformance and KubeVirt conformance tests. This latest workflow is integrated with Ariane so that it is possible to trigger it on a pull request using one of the following commands:

```
/ci-openshift
/ci-openshift {"ocp_version":"4.17.14"}
/ci-openshift {"kubevirt":"true", "ocp_version":"4.17.14"}
```

