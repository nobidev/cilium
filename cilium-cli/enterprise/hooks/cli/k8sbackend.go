//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/yaml"

	ciliumcli "github.com/cilium/cilium/cilium-cli/cli"
	ciliumk8s "github.com/cilium/cilium/cilium-cli/k8s"
)

const (
	k8sBackendServiceAccountName = "cilium-ilb-k8sbackend"
	k8sBackendClusterRoleName    = "cilium-ilb-k8sbackend"

	tokenSecretSuffix = "-token"
	authSecretSuffix  = "-k8sbackend-auth"

	tokenPollInterval = 1 * time.Second
	tokenPollTimeout  = 30 * time.Second

	k8sBackendClusterGroup    = "isovalent.com"
	k8sBackendClusterVersion  = "v1alpha1"
	k8sBackendClusterResource = "lbk8sbackendclusters"
	k8sBackendClusterKind     = "LBK8sBackendCluster"
)

var k8sBackendClusterGVR = schema.GroupVersionResource{
	Group:    k8sBackendClusterGroup,
	Version:  k8sBackendClusterVersion,
	Resource: k8sBackendClusterResource,
}

func k8sBackendLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "cilium-ilb-k8sbackend",
		"app.kubernetes.io/managed-by": "cilium-cli",
	}
}

type K8sBackendAddClusterOptions struct {
	SecretNamespace                 string
	TargetNamespace                 string
	ExternalClusterName             string
	ExternalKubeconfig              string
	ExternalKubeconfigContext       string
	ExternalServiceAccountNamespace string
	ExternalNamespaces              []string
	DryRun                          bool
}

func NewCmdK8sBackend() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "k8s",
		Short:   "Manage Kubernetes backend clusters for cross-cluster load balancing",
		Long:    `Commands for managing K8sBackendCluster resources that enable cross-cluster load balancing.`,
		Aliases: []string{"kubernetes"},
	}

	cmd.AddCommand(newCmdK8sBackendAddCluster())

	return cmd
}

func newCmdK8sBackendAddCluster() *cobra.Command {
	opts := &K8sBackendAddClusterOptions{
		SecretNamespace:                 "cilium-secrets",
		ExternalServiceAccountNamespace: "kube-system",
	}

	cmd := &cobra.Command{
		Use:   "addcluster",
		Short: "Add a remote Kubernetes cluster as a backend source",
		Long: `Add a remote Kubernetes cluster as a backend source for cross-cluster load balancing.

This command:
1. Creates a ServiceAccount, ClusterRole, and ClusterRoleBinding in the target cluster
2. Retrieves the ServiceAccount token
3. Builds a kubeconfig from the token and target cluster CA/server
4. Creates a Secret containing the kubeconfig in the ILB cluster
5. Generates an LBK8sBackendCluster manifest

Example:
  cilium lb k8s addcluster --external-cluster-name us-west-2 \
    --external-kubeconfig /path/to/us-west-2.kubeconfig \
    --external-kubeconfig-context us-west-2 \
    --context ilb-cluster`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAddCluster(cmd.Context(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.ExternalClusterName,
		"external-cluster-name", "",
		"Name for the LBK8sBackendCluster resource (required)")
	flags.StringVar(&opts.ExternalKubeconfig,
		"external-kubeconfig", "",
		"Path to kubeconfig for the external cluster (required)")
	flags.StringVar(&opts.ExternalKubeconfigContext,
		"external-kubeconfig-context", "",
		"Context in the external kubeconfig to use")
	flags.StringVar(&opts.SecretNamespace,
		"secret-namespace", opts.SecretNamespace,
		"Namespace for the authentication secret in the ILB cluster")
	flags.StringVar(&opts.TargetNamespace,
		"target-namespace", "",
		"Namespace where ILB resources should be created")
	flags.StringVar(&opts.ExternalServiceAccountNamespace,
		"external-service-account-namespace",
		opts.ExternalServiceAccountNamespace,
		"Namespace for the ServiceAccount in the external cluster")
	flags.StringSliceVar(&opts.ExternalNamespaces,
		"external-namespaces", nil,
		"Namespaces to watch for services on the external cluster (empty = all)")
	flags.BoolVar(&opts.DryRun,
		"dry-run", false,
		"Print what would be done without making changes")

	cmd.MarkFlagRequired("external-cluster-name")
	cmd.MarkFlagRequired("external-kubeconfig")

	return cmd
}

func runAddCluster(ctx context.Context, opts *K8sBackendAddClusterOptions) error {
	targetConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: opts.ExternalKubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: opts.ExternalKubeconfigContext},
	).ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to build target cluster config: %w", err)
	}

	targetClient, err := kubernetes.NewForConfig(targetConfig)
	if err != nil {
		return fmt.Errorf("failed to create target cluster client: %w", err)
	}

	fmt.Printf("Connected to target cluster: %s\n", targetConfig.Host)

	if err := ensureServiceAccount(ctx, targetClient, opts); err != nil {
		return err
	}
	if err := ensureClusterRole(ctx, targetClient, opts); err != nil {
		return err
	}
	if err := ensureClusterRoleBinding(ctx, targetClient, opts); err != nil {
		return err
	}

	if opts.DryRun {
		fmt.Println("\n[dry-run] Would retrieve ServiceAccount token and create Secret in ILB cluster")
		manifestYAML, _, err := generateManifest(opts)
		if err != nil {
			return err
		}
		fmt.Printf("---\n%s", string(manifestYAML))
		return nil
	}

	tokenSecret, err := ensureTokenSecret(ctx, targetClient, opts)
	if err != nil {
		return err
	}

	// Build a kubeconfig from the token and target cluster info
	kubeconfigBytes, err := buildKubeconfig(
		targetConfig.Host,
		tokenSecret.Data["ca.crt"],
		tokenSecret.Data["token"],
	)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	ilbClient := ciliumcli.RootK8sClient
	fmt.Printf("\nConnected to ILB cluster: %s\n", ilbClient.Config.Host)

	if err := ensureAuthSecret(ctx, ilbClient, opts, kubeconfigBytes); err != nil {
		return err
	}

	manifestYAML, obj, err := generateManifest(opts)
	if err != nil {
		return err
	}

	return applyManifest(ctx, ilbClient, opts, manifestYAML, obj)
}

func ensureServiceAccount(ctx context.Context, client *kubernetes.Clientset, opts *K8sBackendAddClusterOptions) error {
	fmt.Printf("\nCreating ServiceAccount %s/%s in target cluster...\n",
		opts.ExternalServiceAccountNamespace, k8sBackendServiceAccountName)

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      k8sBackendServiceAccountName,
			Namespace: opts.ExternalServiceAccountNamespace,
			Labels:    k8sBackendLabels(),
		},
	}

	if opts.DryRun {
		fmt.Println("[dry-run] Would create ServiceAccount:")
		data, err := yaml.Marshal(sa)
		if err != nil {
			return fmt.Errorf("failed to marshal ServiceAccount: %w", err)
		}
		fmt.Printf("%s", data)
		return nil
	}

	_, err := client.CoreV1().ServiceAccounts(
		opts.ExternalServiceAccountNamespace,
	).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create ServiceAccount: %w", err)
	}
	if k8serrors.IsAlreadyExists(err) {
		fmt.Println("ServiceAccount already exists, skipping")
	} else {
		fmt.Println("Created ServiceAccount")
	}
	return nil
}

func ensureClusterRole(ctx context.Context, client *kubernetes.Clientset, opts *K8sBackendAddClusterOptions) error {
	fmt.Printf("\nCreating ClusterRole %s in target cluster...\n", k8sBackendClusterRoleName)

	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   k8sBackendClusterRoleName,
			Labels: k8sBackendLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list", "watch", "update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	if opts.DryRun {
		fmt.Println("[dry-run] Would create ClusterRole:")
		data, err := yaml.Marshal(clusterRole)
		if err != nil {
			return fmt.Errorf("failed to marshal ClusterRole: %w", err)
		}
		fmt.Printf("%s", data)
		return nil
	}

	_, err := client.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create ClusterRole: %w", err)
	}
	if k8serrors.IsAlreadyExists(err) {
		fmt.Println("ClusterRole already exists, skipping")
	} else {
		fmt.Println("Created ClusterRole")
	}
	return nil
}

func ensureClusterRoleBinding(
	ctx context.Context,
	client *kubernetes.Clientset,
	opts *K8sBackendAddClusterOptions,
) error {
	fmt.Printf("\nCreating ClusterRoleBinding %s in target cluster...\n", k8sBackendClusterRoleName)

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   k8sBackendClusterRoleName,
			Labels: k8sBackendLabels(),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     k8sBackendClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      k8sBackendServiceAccountName,
				Namespace: opts.ExternalServiceAccountNamespace,
			},
		},
	}

	if opts.DryRun {
		fmt.Println("[dry-run] Would create ClusterRoleBinding:")
		data, err := yaml.Marshal(crb)
		if err != nil {
			return fmt.Errorf("failed to marshal ClusterRoleBinding: %w", err)
		}
		fmt.Printf("%s", data)
		return nil
	}

	_, err := client.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create ClusterRoleBinding: %w", err)
	}
	if k8serrors.IsAlreadyExists(err) {
		fmt.Println("ClusterRoleBinding already exists, skipping")
	} else {
		fmt.Println("Created ClusterRoleBinding")
	}
	return nil
}

func ensureTokenSecret(
	ctx context.Context,
	client *kubernetes.Clientset,
	opts *K8sBackendAddClusterOptions,
) (*corev1.Secret, error) {
	fmt.Printf("\nCreating token for ServiceAccount...\n")

	tokenRequest := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      k8sBackendServiceAccountName + tokenSecretSuffix,
			Namespace: opts.ExternalServiceAccountNamespace,
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": k8sBackendServiceAccountName,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	_, err := client.CoreV1().Secrets(opts.ExternalServiceAccountNamespace).Create(
		ctx, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		if !k8serrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("failed to create ServiceAccount token secret: %w", err)
		}
		fmt.Println("Token secret already exists")
	} else {
		fmt.Println("Created token secret")
	}

	var tokenSecret *corev1.Secret
	err = wait.PollUntilContextTimeout(
		ctx, tokenPollInterval, tokenPollTimeout, true,
		func(ctx context.Context) (bool, error) {
			var getErr error
			tokenSecret, getErr = client.CoreV1().Secrets(
				opts.ExternalServiceAccountNamespace,
			).Get(ctx, k8sBackendServiceAccountName+tokenSecretSuffix, metav1.GetOptions{})
			if getErr != nil {
				return false, fmt.Errorf("failed to get token secret: %w", getErr)
			}
			if len(tokenSecret.Data["token"]) > 0 {
				return true, nil
			}
			fmt.Println("Waiting for token to be populated...")
			return false, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"token was not populated within %s: %w", tokenPollTimeout, err)
	}

	return tokenSecret, nil
}

func buildKubeconfig(server string, caData, token []byte) ([]byte, error) {
	kubeconfig := clientcmdapi.NewConfig()

	cluster := clientcmdapi.NewCluster()
	cluster.Server = server
	cluster.CertificateAuthorityData = caData
	kubeconfig.Clusters["default"] = cluster

	authInfo := clientcmdapi.NewAuthInfo()
	authInfo.Token = string(token)
	kubeconfig.AuthInfos["default"] = authInfo

	kctx := clientcmdapi.NewContext()
	kctx.Cluster = "default"
	kctx.AuthInfo = "default"
	kubeconfig.Contexts["default"] = kctx
	kubeconfig.CurrentContext = "default"

	return clientcmd.Write(*kubeconfig)
}

func ensureAuthSecret(
	ctx context.Context,
	ilbClient *ciliumk8s.Client,
	opts *K8sBackendAddClusterOptions,
	kubeconfigBytes []byte,
) error {

	secretName := opts.ExternalClusterName + authSecretSuffix
	fmt.Printf("Creating Secret %s/%s in ILB cluster...\n", opts.SecretNamespace, secretName)

	labels := k8sBackendLabels()
	labels["k8sbackendcluster"] = opts.ExternalClusterName

	authSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: opts.SecretNamespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"kubeconfig": kubeconfigBytes,
		},
	}

	_, err := ilbClient.Clientset.CoreV1().Namespaces().Get(ctx, opts.SecretNamespace, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: opts.SecretNamespace,
				},
			}
			_, err = ilbClient.Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create namespace %s: %w", opts.SecretNamespace, err)
			}
			fmt.Printf("Created namespace %s\n", opts.SecretNamespace)
		} else {
			return fmt.Errorf("failed to get namespace %s: %w", opts.SecretNamespace, err)
		}
	}

	_, err = ilbClient.Clientset.CoreV1().Secrets(opts.SecretNamespace).Create(ctx, authSecret, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			_, err = ilbClient.Clientset.CoreV1().Secrets(opts.SecretNamespace).Update(
				ctx, authSecret, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update Secret: %w", err)
			}
			fmt.Println("Updated existing Secret")
		} else {
			return fmt.Errorf("failed to create Secret: %w", err)
		}
	} else {
		fmt.Println("Created Secret")
	}

	return nil
}

func generateManifest(
	opts *K8sBackendAddClusterOptions,
) ([]byte, *unstructured.Unstructured, error) {
	fmt.Printf("\nGenerating LBK8sBackendCluster manifest...\n")

	secretName := opts.ExternalClusterName + authSecretSuffix

	spec := map[string]any{
		"authentication": map[string]any{
			"secretRef": map[string]any{
				"name":      secretName,
				"namespace": opts.SecretNamespace,
			},
		},
	}

	if opts.TargetNamespace != "" {
		spec["targetNamespace"] = opts.TargetNamespace
	}

	if len(opts.ExternalNamespaces) > 0 {
		discoveryConfig := map[string]any{
			"name":       "default",
			"namespaces": opts.ExternalNamespaces,
		}
		spec["serviceDiscovery"] = []any{discoveryConfig}
	}

	k8sbc := map[string]any{
		"apiVersion": k8sBackendClusterGroup + "/" + k8sBackendClusterVersion,
		"kind":       k8sBackendClusterKind,
		"metadata": map[string]any{
			"name": opts.ExternalClusterName,
		},
		"spec": spec,
	}

	manifestYAML, err := yaml.Marshal(k8sbc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	obj := &unstructured.Unstructured{Object: k8sbc}
	return manifestYAML, obj, nil
}

func applyManifest(
	ctx context.Context,
	ilbClient *ciliumk8s.Client,
	opts *K8sBackendAddClusterOptions,
	manifestYAML []byte,
	obj *unstructured.Unstructured,
) error {
	fmt.Printf("\nApplying LBK8sBackendCluster to ILB cluster...\n")

	_, err := ilbClient.DynamicClientset.Resource(k8sBackendClusterGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			existing, err := ilbClient.DynamicClientset.Resource(k8sBackendClusterGVR).Get(
				ctx, opts.ExternalClusterName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get existing LBK8sBackendCluster: %w", err)
			}
			obj.SetResourceVersion(existing.GetResourceVersion())
			_, err = ilbClient.DynamicClientset.Resource(k8sBackendClusterGVR).Update(ctx, obj, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update LBK8sBackendCluster: %w", err)
			}
			fmt.Println("Updated existing LBK8sBackendCluster")
		} else {
			return fmt.Errorf("failed to create LBK8sBackendCluster: %w", err)
		}
	} else {
		fmt.Println("Created LBK8sBackendCluster")
	}

	fmt.Printf("\nLBK8sBackendCluster '%s' has been applied to the ILB cluster.\n",
		opts.ExternalClusterName)
	fmt.Printf("Manifest:\n---\n%s", string(manifestYAML))
	return nil
}
