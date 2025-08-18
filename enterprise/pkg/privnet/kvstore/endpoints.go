//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package kvstore

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"path"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/time"
)

// EndpointsPrefix is the kvstore prefix for the private network endpoints.
//
// WARNING - STABLE API: Changing the structure or values of this will
// break backwards compatibility
var EndpointsPrefix = path.Join(kvstore.BaseKeyPrefix, "state", "privneteps", "v1")

// Endpoint represents a single private network endpoint, for either IPv4 or IPv6.
type Endpoint struct {
	// ActivatedAt is the instant in time in which this entry was marked as active.
	ActivatedAt time.Time `json:"activatedAt,omitzero"`

	// IP is the endpoint IP from the pod network point of view.
	IP netip.Addr `json:"ip" validate:"required"`

	// The name identifying the target endpoint.
	Name string `json:"name" validate:"required,dns1123-subdomain"`

	// Network contains the identifiers from the private network point of view.
	Network Network `json:"network" validate:"required"`

	// Source identifies the resource propagating the endpoint information.
	Source Source `json:"source" validate:"required"`
}

// Network contains the identifiers from the private network point of view.
type Network struct {
	// Name is the name of the target private network.
	Name string `json:"name" validate:"required,dns1123-subdomain"`

	// IP is the IP addresses of the endpoint.
	IP netip.Addr `json:"ip" validate:"required"`

	// MAC is the MAC address of the endpoint.
	MAC mac.MAC `json:"mac" validate:"required,len=6"`
}

// Source identifies the resource propagating the endpoint information.
type Source struct {
	Cluster   string `json:"cluster" validate:"required,cluster-name"`
	Namespace string `json:"namespace" validate:"required,dns1123-label"`
	Name      string `json:"name" validate:"required,dns1123-subdomain"`
}

func (s Source) String() string {
	return s.Cluster + "/" + s.Namespace + "/" + s.Name
}

// GetKeyName returns the kvstore key to be used for the private network endpoint.
func (e *Endpoint) GetKeyName() string {
	// WARNING - STABLE API: Changing the structure of the key may break
	// backwards compatibility
	return path.Join(e.Source.Cluster, e.Network.Name, e.IP.String())
}

// Marshal returns the global service object as JSON byte slice
func (e *Endpoint) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Unmarshal parses the JSON byte slice and updates the receiver
func (e *Endpoint) Unmarshal(key string, data []byte) error {
	var endpoint Endpoint

	if err := json.Unmarshal(data, &endpoint); err != nil {
		return err
	}

	if err := endpoint.validate(key); err != nil {
		return err
	}

	*e = endpoint
	return nil
}

func (e *Endpoint) validate(key string) error {
	if err := validate.Struct(e); err != nil {
		return err
	}

	expected := path.Join(e.Network.Name, e.IP.String())
	if expected != key {
		return fmt.Errorf("endpoint does not match provided key: got %q, expected %q", key, expected)
	}

	return nil
}

// ValidatingEndpoint wraps an Endpoint to perform additional validations at
// unmarshal time.
type ValidatingEndpoint struct {
	Endpoint

	validators []endpointValidator
}

func (vn *ValidatingEndpoint) Unmarshal(key string, data []byte) error {
	if err := vn.Endpoint.Unmarshal(key, data); err != nil {
		return err
	}

	for _, validator := range vn.validators {
		if err := validator(key, &vn.Endpoint); err != nil {
			return err
		}
	}

	return nil
}

type endpointValidator func(key string, e *Endpoint) error

// EndpointClusterNameValidator returns a validator enforcing that the cluster field
// of the unmarshaled endpoint matches the provided one.
func EndpointClusterNameValidator(clusterName string) endpointValidator {
	return func(_ string, e *Endpoint) error {
		if e.Source.Cluster != clusterName {
			return fmt.Errorf("unexpected cluster name: got %q, expected %q", e.Source.Cluster, clusterName)
		}
		return nil
	}
}

// EndpointKeyCreator returns a store.KeyCreator for private network endpoints,
// configuring the specified extra validators.
func EndpointKeyCreator(validators ...endpointValidator) store.KeyCreator {
	return func() store.Key {
		return &ValidatingEndpoint{validators: validators}
	}
}
