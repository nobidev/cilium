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

import (
	"context"
	"fmt"
	"strings"
	"text/template"
)

type coreDNSContainer struct {
	dockerContainer
	Domain  string
	Records []*coreDNSRecord
}

type coreDNSRecord struct {
	// Hostname (without domain)
	Hostname string
	// IP addresses
	IP string
}

const coreDNSTemplate = `
. {
    forward . /etc/resolv.conf
}
{{ .Domain }} {
    hosts {
    {{- range $index, $record := .Records }}
        {{ $record.IP }} {{ $record.Hostname }}.{{ $.Domain }}
    {{- end }}
    }
    errors
    log
}
`

func (c *coreDNSContainer) reload(ctx context.Context) error {
	builder := &strings.Builder{}

	// Render Corefile
	tmpl, err := template.New("Corefile").Parse(coreDNSTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse Corefile template: %w", err)
	}

	if err := tmpl.Execute(builder, c); err != nil {
		return fmt.Errorf("failed to render Corefile template: %w", err)
	}

	conf := builder.String()

	fmt.Printf("Reloading CoreDNS configuration...\n")

	// Upload new Corefile
	if err := c.Copy(ctx, []byte(conf), "Corefile", "/tmp"); err != nil {
		return fmt.Errorf("failed to copy Corefile: %w", err)
	}

	// Send SIGUSR1 to CoreDNS to reload the configuration
	if err := c.Kill(ctx, "SIGUSR1"); err != nil {
		return fmt.Errorf("failed to send signal to CoreDNS: %w", err)
	}

	return nil
}

// addDNSRecords adds DNS records to the CoreDNS container and reloads the
// configuration. Note that the reload is done asynchronously and may fail.
// Therefore, callers are responsible for ensuring that the name is actually
// resolvable.
func (c *coreDNSContainer) AddDNSRecords(ctx context.Context, records []*coreDNSRecord) error {
	c.Records = append(c.Records, records...)
	return c.reload(ctx)
}
