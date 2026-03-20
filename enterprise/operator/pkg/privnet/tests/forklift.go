// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tests

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"

	whcfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
	forklift "github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/forklift"
	"github.com/cilium/cilium/pkg/lock"
)

func ForkliftTestCell(t testing.TB) cell.Cell {
	return cell.Group(
		cell.Provide(
			func(lc cell.Lifecycle, cfg whcfg.Config) (*inventory, error) {
				return newInventory(lc, t.TempDir(), cfg)
			},

			(*inventory).cmds,
		),

		cell.DecorateAll(
			func(i *inventory) forklift.Config {
				return forklift.Config{
					URL:             i.url,
					CAPath:          i.caPath,
					BearerTokenPath: i.tokenPath,
				}
			},
		),
	)
}

type inventory struct {
	url       string
	tokenPath string
	caPath    string

	mu        lock.RWMutex
	providers map[string]provider
}

type provider struct {
	vms map[string]string
}

func newInventory(lc cell.Lifecycle, tmp string, cfg whcfg.Config) (*inventory, error) {
	var i = &inventory{
		tokenPath: path.Join(tmp, "token"),
		caPath:    path.Join(tmp, "ca.crt"),
		providers: make(map[string]provider),
	}

	if !cfg.Enabled {
		return i, nil
	}

	// We should not start a server in a provide function, but we need to access
	// the TLS material that gets initialized there, and this is a test, so ...
	srv := httptest.NewTLSServer(i.handlers())
	i.url = srv.URL

	if err := os.WriteFile(i.caPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw},
	), 0644); err != nil {
		return nil, fmt.Errorf("writing ca.crt: %w", err)
	}

	err := os.WriteFile(i.tokenPath, []byte("super-secret-token"), 0644)
	if err != nil {
		return nil, fmt.Errorf("writing token: %w", err)
	}

	lc.Append(
		cell.Hook{
			OnStop: func(cell.HookContext) error {
				srv.Close()
				return nil
			},
		},
	)

	return i, nil
}

func (i *inventory) cmds() uhive.ScriptCmdsOut {
	var handler = func(save func(p *provider, id, data string)) func(*script.State, ...string) (script.WaitFunc, error) {
		return func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
			}

			pid, infile := args[0], args[1]

			data, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", infile, err)
			}

			var id struct {
				ID string `json:"id"`
			}

			err = json.Unmarshal(data, &id)
			switch {
			case err != nil:
				return nil, fmt.Errorf("parsing ID: %w", err)
			case id.ID == "":
				return nil, fmt.Errorf("parsing ID: no ID found")
			}

			i.mu.Lock()
			defer i.mu.Unlock()

			provider := i.providers[pid]
			save(&provider, id.ID, string(data))
			i.providers[pid] = provider
			return nil, nil
		}
	}

	return uhive.NewScriptCmds(map[string]script.Cmd{
		"inventory/register-vm": script.Command(
			script.CmdUsage{
				Summary: "Register a VM in the inventory service",
				Args:    "provider vm.json",
			},
			handler(func(p *provider, id, data string) {
				if p.vms == nil {
					p.vms = make(map[string]string)
				}

				p.vms[id] = data
			}),
		),
	})
}

func (i *inventory) handlers() *http.ServeMux {
	handler := func(peek func(p provider, id string) (string, bool)) http.HandlerFunc {
		return func(w http.ResponseWriter, req *http.Request) {
			if req.Header.Get("Authorization") != "Bearer super-secret-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			i.mu.RLock()
			defer i.mu.RUnlock()

			provider, ok := i.providers[req.PathValue("pid")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			got, ok := peek(provider, req.PathValue("id"))
			if !ok {
				w.WriteHeader(http.StatusNotFound)
			}

			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(got))
		}
	}

	var mux = http.NewServeMux()

	mux.HandleFunc("/providers/vsphere/{pid}/vms/{id}", handler(
		func(p provider, id string) (string, bool) {
			got, ok := p.vms[id]
			return got, ok
		},
	))

	return mux
}
