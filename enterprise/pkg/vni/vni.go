// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vni

import (
	"errors"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// VNI represents a VXLAN Network Identifier. This object is directly
// comparable with == operator and can be a key of the maps. It internally
// keeps the flag that the VNI is valid or not. To get a valid VNI, you must
// use one of the constructor provided by this package. Direct initialization
// like VNI{} always produces an invalid VNI (VNI{} == MustFromUint32(0) is
// false).
type VNI struct {
	// The value is kept as 32bit, but the value is guaranteed to be within
	// 24bit if the valid bit is set.
	val uint32
}

var (
	ErrOutOfRange = errors.New("out of range VNI value")
)

const (
	validMask = 0x01000000
	rangeMask = 0x00ffffff
)

func inRange(v uint32) bool {
	return v <= rangeMask
}

func FromUint32(v uint32) (VNI, error) {
	if !inRange(v) {
		return VNI{}, ErrOutOfRange
	}
	return VNI{val: v | validMask}, nil
}

func MustFromUint32(v uint32) VNI {
	vni, err := FromUint32(v)
	if err != nil {
		panic(err)
	}
	return vni
}

func Parse(s string) (VNI, error) {
	v64, err := strconv.ParseUint(s, 0, 24)
	if err != nil {
		return VNI{}, err
	}
	return VNI{val: uint32(v64) | validMask}, nil
}

func MustParse(s string) VNI {
	vni, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return vni
}

func (v VNI) IsValid() bool {
	return v.val&validMask != 0
}

func (v VNI) AsUint32() uint32 {
	return v.val & rangeMask
}

func (v VNI) String() string {
	if !v.IsValid() {
		return ""
	}
	return strconv.FormatUint(uint64(v.val&rangeMask), 10)
}

func (v VNI) MarshalYAML() (any, error) {
	if !v.IsValid() {
		return nil, nil
	}
	return v.AsUint32(), nil
}

func (v *VNI) UnmarshalYAML(value *yaml.Node) error {
	if value.Value == "" {
		*v = VNI{}
		return nil
	}
	vni, err := Parse(value.Value)
	if err != nil {
		return err
	}
	*v = vni
	return nil
}

func (v VNI) MarshalJSON() ([]byte, error) {
	if !v.IsValid() {
		return []byte("null"), nil
	}
	return []byte(v.String()), nil
}

func (v *VNI) UnmarshalJSON(bs []byte) error {
	if string(bs) == "null" {
		*v = VNI{}
		return nil
	}
	vni, err := Parse(string(bs))
	if err != nil {
		return err
	}
	*v = vni
	return nil
}
