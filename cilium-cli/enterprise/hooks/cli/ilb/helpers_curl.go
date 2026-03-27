//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ilb

import "strings"

func curlCmdVerbose(extra string) string {
	return "curl -w '%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}' --silent --show-error --retry 3 --retry-all-errors --retry-delay 1 " + extra
}

func curlCmd(extra string) string {
	return "curl --silent --show-error --retry 3 --retry-all-errors --retry-delay 1 " + extra
}

func curlCmdWithHeaders(cmd string, headers map[string]string) string {
	if len(headers) == 0 {
		return cmd
	}

	var builder strings.Builder
	builder.WriteString(cmd)
	for key, value := range headers {
		builder.WriteString(" -H '")
		builder.WriteString(key)
		builder.WriteString(":")
		builder.WriteString(value)
		builder.WriteString("'")
	}

	return builder.String()
}
