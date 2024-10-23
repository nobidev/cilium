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

//go:embed healthcheck_json_format.json
var healthCheckJSONFormat string

//go:embed tcp_text_format.txt
var tcpTextFormat string

//go:embed tcp_json_format.json
var tcpJSONFormat string

//go:embed tls_text_format.txt
var tlsTextFormat string

//go:embed tls_json_format.json
var tlsJSONFormat string

//go:embed http_text_format.txt
var httpTextFormat string

//go:embed http_json_format.json
var httpJSONFormat string

type AccessLogType int

const (
	AccessLogTypeHealthCheck AccessLogType = iota
	AccessLogTypeTCP
	AccessLogTypeTLS
	AccessLogTypeHTTP
)

func GetFormatText(alType AccessLogType) string {
	formatString := getFormatText(alType)

	formatString = strings.ReplaceAll(formatString, "\n", " ")
	formatString = strings.TrimSpace(formatString)

	return formatString
}

func getFormatText(alType AccessLogType) string {
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

func GetFormatJSON(alType AccessLogType) string {
	formatString := getFormatJSON(alType)

	formatString = strings.ReplaceAll(formatString, "\n", " ")

	return formatString
}

func getFormatJSON(alType AccessLogType) string {
	switch alType {
	case AccessLogTypeHealthCheck:
		return healthCheckJSONFormat
	case AccessLogTypeTCP:
		return tcpJSONFormat
	case AccessLogTypeTLS:
		return tlsJSONFormat
	case AccessLogTypeHTTP:
		return httpJSONFormat
	}

	return ""
}
