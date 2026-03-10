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
	"fmt"

	"github.com/spf13/pflag"
)

type Config struct {
	EnableEncryptionPolicy           bool
	EncryptionPolicyFallbackBehavior string
}

// IsEnabled returns whether encryption policy is enabled
func (c Config) IsEnabled() bool {
	return c.EnableEncryptionPolicy
}

// FallbackEncrypt returns true when the fallback behavior is not "plaintext",
// meaning all traffic is encrypted by default unless opted out via plaintextPeers.
func (c Config) FallbackEncrypt() bool {
	return c.EncryptionPolicyFallbackBehavior != "plaintext"
}

// Validate checks that the fallback behavior is a valid value.
func (c Config) Validate() error {
	if !c.EnableEncryptionPolicy {
		return nil
	}
	switch c.EncryptionPolicyFallbackBehavior {
	case "encrypt", "plaintext":
		return nil
	default:
		return fmt.Errorf("invalid encryption-policy-fallback-behavior %q: accepted values are \"encrypt\" and \"plaintext\"",
			c.EncryptionPolicyFallbackBehavior)
	}
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-encryption-policy", c.EnableEncryptionPolicy, "Enable support for encryption policies. When enabled, only selected traffic will be encrypted.")
	flags.String("encryption-policy-fallback-behavior", c.EncryptionPolicyFallbackBehavior, "Defines the behavior for traffic not selected by an encryption policy. Accepted values: \"encrypt\" (default), \"plaintext\".")
}
