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

import "github.com/spf13/pflag"

type Config struct {
	EnableEncryptionPolicy bool
}

// IsEnabled returns whether encryption policy is enabled
func (c Config) IsEnabled() bool {
	return c.EnableEncryptionPolicy
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-encryption-policy", c.EnableEncryptionPolicy, "Enable support for encryption policies. When enabled, only selected traffic will be encrypted.")
}
