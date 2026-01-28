// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,isovalent,loadbalancer},singular="lbk8sbackendcluster",path="lbk8sbackendclusters",scope="Cluster",shortName={lbkbc}
// +kubebuilder:printcolumn:JSONPath=".status.status",name="Status",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// LBK8sBackendCluster defines a remote Kubernetes cluster whose LoadBalancer
// services should be discovered and load balanced by the ILB control plane.
type LBK8sBackendCluster struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`

	// +deepequal-gen=false
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec LBK8sBackendClusterSpec `json:"spec"`

	// +optional
	Status *LBK8sBackendClusterStatus `json:"status,omitempty"`
}

type LBK8sBackendClusterSpec struct {
	// Authentication specifies how to authenticate to the remote cluster.
	//
	// +required
	Authentication LBK8sBackendClusterAuth `json:"authentication"`
}

type LBK8sBackendClusterAuth struct {
	// SecretRef references a Secret containing authentication credentials.
	// The secret must contain a "kubeconfig" key with a valid kubeconfig file.
	//
	// +required
	SecretRef LBK8sBackendClusterSecretRef `json:"secretRef"`
}

type LBK8sBackendClusterSecretRef struct {
	// +required
	Namespace string `json:"namespace"`

	// +required
	Name string `json:"name"`
}

type LBK8sBackendClusterStatus struct {
	// Status is one of "OK" or "ConditionNotMet".
	// For detailed information, see the Message field of each condition.
	//
	// +optional
	Status *ExtLBResourceStatus `json:"status,omitempty"`

	// LastSyncTime is the last time the cluster connection was synced.
	//
	// +optional
	// +deepequal-gen=false
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Conditions represent the latest available observations.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +deepequal-gen=false

// LBK8sBackendClusterList is a list of LBK8sBackendCluster resources.
type LBK8sBackendClusterList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []LBK8sBackendCluster `json:"items"`
}

func (r *LBK8sBackendCluster) GetStatusCondition(conditionType string) *metav1.Condition {
	if r.Status == nil {
		return nil
	}
	for _, c := range r.Status.Conditions {
		if c.Type == conditionType {
			return &c
		}
	}
	return nil
}

func (r *LBK8sBackendCluster) UpsertStatusCondition(conditionType string, condition metav1.Condition) {
	if r.Status == nil {
		r.Status = &LBK8sBackendClusterStatus{}
	}
	conditionExists := false
	for i, c := range r.Status.Conditions {
		if c.Type == conditionType {
			if c.Status != condition.Status ||
				c.Reason != condition.Reason ||
				c.Message != condition.Message ||
				c.ObservedGeneration != condition.ObservedGeneration {
				// transition -> update condition
				r.Status.Conditions[i] = condition
			}
			conditionExists = true
			break
		}
	}

	if !conditionExists {
		r.Status.Conditions = append(r.Status.Conditions, condition)
	}
}

func (r *LBK8sBackendCluster) UpdateResourceStatus() {
	if r.Status == nil {
		r.Status = &LBK8sBackendClusterStatus{}
	}
	resourceStatus := ExtLBResourceStatusOK

	for _, c := range r.Status.Conditions {
		if c.Status == metav1.ConditionFalse {
			resourceStatus = ExtLBResourceStatusConditionNotMet
			break
		}
	}

	r.Status.Status = &resourceStatus
}

// Condition types for LBK8sBackendCluster
const (
	ConditionTypeClusterConnected = "extlb.cilium.io/ClusterConnected"
)

// Condition reasons for LBK8sBackendCluster
const (
	ClusterConnectedReasonConnected        = "Connected"
	ClusterConnectedReasonConnectionFailed = "ConnectionFailed"
)

// ExtLBResourceStatus represents the status of an external load balancer
// resource.  Note that unlike the use of LBResourceStatus, this status is used
// with a pointer type, so the initial value of "nil" means "Unknown"
// +kubebuilder:validation:Enum=OK;ConditionNotMet
type ExtLBResourceStatus string

const (
	// Status OK: everything is OK
	ExtLBResourceStatusOK ExtLBResourceStatus = "OK"
	// Status ConditionNotMet: At least one condition isn't met
	ExtLBResourceStatusConditionNotMet ExtLBResourceStatus = "ConditionNotMet"
)
