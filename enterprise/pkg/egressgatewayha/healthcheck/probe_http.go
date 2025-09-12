// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthcheck

import "net/http"

type httpProber struct {
	netClient *http.Client
	url       string
}

func (h *httpProber) runHealthcheckProbe() bool {
	r, err := h.netClient.Get(h.url)
	if err != nil {
		return false
	}
	defer r.Body.Close()

	return r.StatusCode == 200
}

func (h *httpProber) mode() probeMode {
	return HTTP
}
