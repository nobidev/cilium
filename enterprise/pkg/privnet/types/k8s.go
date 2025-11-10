//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/mac"
)

const (
	// PrivateNetworkAnnotationPrefix is the common prefix for private network annotations.
	PrivateNetworkAnnotationPrefix = "privnet.isovalent.com"

	// PrivateNetworkAnnotation is the name of the annotation to attach pods to a particular
	// private network.
	PrivateNetworkAnnotation = "network.v1alpha1.isovalent.com/network-attachment"

	// PrivateNetworkInactiveAnnotation is the name of the annotation which marks the pod inactive.
	PrivateNetworkInactiveAnnotation = "network.v1alpha1.isovalent.com/inactive"

	// PrivateNetworkINBHealthServerPortAnnotation is the name of the node annotation propagating
	// the TCP port the privnet health server is listening to.
	PrivateNetworkINBHealthServerPortAnnotation = PrivateNetworkAnnotationPrefix + "/inb-health-server-port"
)

// NetworkAttachment is the value of PrivateNetworkAnnotation (encoded as JSON)
type NetworkAttachment struct {
	Network string     `json:"network"`
	IPv4    netip.Addr `json:"ipv4,omitzero"`
	IPv6    netip.Addr `json:"ipv6,omitzero"`
	MAC     mac.MAC    `json:"mac,omitempty"`
}

func ExtractNetworkAttachmentAnnotation(annotations map[string]string) (*NetworkAttachment, error) {
	raw, found := annotations[PrivateNetworkAnnotation]
	if !found {
		return nil, nil // not found
	}

	attachment := &NetworkAttachment{}
	err := json.Unmarshal([]byte(raw), attachment)
	if err != nil {
		return nil, fmt.Errorf("invalid value in %q annotation: %w", PrivateNetworkAnnotation, err)
	}

	return attachment, nil
}

func ExtractInactiveAnnotation(annotations map[string]string) (inactive bool, err error) {
	raw, found := annotations[PrivateNetworkInactiveAnnotation]
	if !found {
		return false, nil // not found means endpoint is active
	}

	inactive, err = strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid value in %q annotation: %w", PrivateNetworkInactiveAnnotation, err)
	}

	return inactive, nil
}
