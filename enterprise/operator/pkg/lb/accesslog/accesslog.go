//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package accesslog

import (
	_ "embed"
	"strings"
)

//go:embed healthcheck_text_format.txt
var healthCheckTextFormat string

//go:embed tcp_text_format.txt
var tcpTextFormat string

//go:embed tls_text_format.txt
var tlsTextFormat string

//go:embed http_text_format.txt
var httpTextFormat string

type AccessLogType int

const (
	AccessLogTypeHealthCheck AccessLogType = iota
	AccessLogTypeTCP
	AccessLogTypeTLS
	AccessLogTypeHTTP
)

func GetFormatString(alType AccessLogType) string {
	formatString := getFormatString(alType)

	formatString = strings.ReplaceAll(formatString, "\n", " ")
	formatString = strings.TrimSpace(formatString)

	return formatString
}

func getFormatString(alType AccessLogType) string {
	switch alType {
	case AccessLogTypeHealthCheck:
		return healthCheckTextFormat
	case AccessLogTypeTCP:
		return tcpTextFormat
	case AccessLogTypeTLS:
		return tlsTextFormat
	case AccessLogTypeHTTP:
		return httpTextFormat
	}

	return ""
}
