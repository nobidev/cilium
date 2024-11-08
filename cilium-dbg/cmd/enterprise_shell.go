//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package cmd

import "io"

// ShellExchange exports the shellExchange function for use in
// enterprise/cilium-dbg until it has been exported in OSS and can be removed
// here.
func ShellExchange(w io.Writer, format string, args ...any) error {
	return shellExchange(w, format, args...)
}
