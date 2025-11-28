/*
Copyright (C) Isovalent, Inc. - All Rights Reserved.

NOTICE: All information contained herein is, and remains the property of
Isovalent Inc and its suppliers, if any. The intellectual and technical
concepts contained herein are proprietary to Isovalent Inc and its suppliers
and may be covered by U.S. and Foreign Patents, patents in process, and are
protected by trade secret or copyright law.  Dissemination of this information
or reproduction of this material is strictly forbidden unless prior written
permission is obtained from Isovalent Inc.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// Run "make" to regenerate code after modifying this file

const (
	APINotAvailableCondition = "APINotAvailable"
	ValuesErrorsCondition    = "ValuesError"
	ProcessingErrorCondition = "ProcessingError"
)

const (
	APIMissingReason                    = "APIMissing"
	APINotMissingReason                 = "APINotMissing"
	ValuesNotReadableReason             = "ValuesNotReadable"
	ValuesReadableReason                = "ValuesReadable"
	ValuesNotProcessedReason            = "ValuesNotProcessed"
	NoProcessingErrorReason             = "NoProcessingError"
	StateRetrievalProcessingErrorReason = "StateRetrievalError"
	HelmProcessingErrorReason           = "HelmError"
	APIProcessingErrorReason            = "APIProcessingError"
)

// CiliumConfigSpec defines the desired state of CiliumConfig
type CiliumConfigSpec struct {
	// wraps raw helm values
	runtime.RawExtension `json:",inline"`
}

// CiliumConfigStatus defines the observed state of CiliumConfig
type CiliumConfigStatus struct {
	// Conditions provides details on the state of the component
	// +listType=atomic
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +operator-sdk:csv:customresourcedefinitions:type=status
	Conditions []metav1.Condition `json:"conditions,omitempty"  patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=ciliumconfigs,scope=Cluster,categories={all,cilium},shortName={cconf,cconfs}
// +kubebuilder:subresource:status

// CiliumConfig defines the configuration of Isovalent Networking for Kubernetes and all its components
// +operator-sdk:csv:customresourcedefinitions:displayName="CiliumConfig"
type CiliumConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CiliumConfigSpec   `json:"spec,omitempty"`
	Status CiliumConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CiliumConfigList contains a list of CiliumConfig
type CiliumConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CiliumConfig{}, &CiliumConfigList{})
}
