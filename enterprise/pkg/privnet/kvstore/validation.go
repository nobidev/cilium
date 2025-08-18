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
	"github.com/go-playground/validator/v10"
	"k8s.io/apimachinery/pkg/util/validation"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

var validate = validator.New(
	validator.WithRequiredStructEnabled(),
)

func init() {
	validate.RegisterValidation(
		"dns1123-subdomain",
		func(fl validator.FieldLevel) bool {
			return len(validation.IsDNS1123Subdomain(fl.Field().String())) == 0
		},
	)

	validate.RegisterValidation(
		"dns1123-label",
		func(fl validator.FieldLevel) bool {
			return len(validation.IsDNS1123Label(fl.Field().String())) == 0
		},
	)

	validate.RegisterValidation(
		"cluster-name",
		func(fl validator.FieldLevel) bool {
			return cmtypes.ValidateClusterName(fl.Field().String()) == nil
		},
	)
}
