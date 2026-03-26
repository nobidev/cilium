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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	admission_v1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	whcfg "github.com/cilium/cilium/enterprise/operator/pkg/privnet/webhook/config"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/safeio"
)

func WebhookTestCell(t testing.TB) cell.Cell {
	return cell.Group(
		cell.Provide(
			func() *webhook {
				return &webhook{
					path: t.TempDir(),
					root: x509.NewCertPool(),
				}
			},
			(*webhook).cmds,
		),

		cell.Invoke(
			(*webhook).generateTLSPair,
		),

		cell.DecorateAll(
			func(cfg whcfg.Config, w *webhook) whcfg.Config {
				if !cfg.Enabled {
					return cfg
				}

				// Attempt to select a free listen port for the webhook. We cannot
				// pass a custom listener, nor let it choose a random port, hence
				// we need to hope that the port is still free once we need it.
				listener, err := net.Listen("tcp", "localhost:0")
				require.NoError(t, err, "net.Listen")
				defer listener.Close()

				cfg.HostPort = listener.Addr().String()
				cfg.TLSKeyFile, cfg.TLSCertFile = w.tlsKeyFile(), w.tlsCertFile()

				return cfg
			},
		),

		ForkliftTestCell(t),
	)
}

type webhook struct {
	path string
	root *x509.CertPool
}

func (w *webhook) tlsKeyFile() string  { return path.Join(w.path, "tls.key") }
func (w *webhook) tlsCertFile() string { return path.Join(w.path, "tls.crt") }

func (w *webhook) cmds(cfg whcfg.Config) uhive.ScriptCmdsOut {
	var (
		admissionScheme = runtime.NewScheme()
		admissionCodecs = serializer.NewCodecFactory(admissionScheme)

		client = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: w.root,

					MinVersion: tls.VersionTLS12,
				},
			},
		}
	)

	admission_v1.AddToScheme(admissionScheme)

	return uhive.NewScriptCmds(map[string]script.Cmd{
		"webhook/admit": script.Command(
			script.CmdUsage{
				Summary: "Post a request to a webhook",
				Args:    "request-path operation file",
				Flags: func(fs *pflag.FlagSet) {
					fs.Duration("timeout", time.Second, "Timeout")
					fs.StringP("out", "o", "", "File to write to instead of stdout")
					fs.Bool("expect-no-changes", false, "Expect that the response contains no patch, and fail otherwise")
				},
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 3 {
					return nil, fmt.Errorf("%w: expected number of arguments", script.ErrUsage)
				}

				reqpath, op, infile := args[0], admission_v1.Operation(strings.ToUpper(args[1])), args[2]
				switch op {
				case admission_v1.Create, admission_v1.Update, admission_v1.Delete, admission_v1.Connect:
				default:
					return nil, fmt.Errorf("operation %q is not supported", op)
				}

				timeout, err := s.Flags.GetDuration("timeout")
				if err != nil {
					return nil, fmt.Errorf("reading timeout flag: %w", err)
				}

				outfile, err := s.Flags.GetString("out")
				if err != nil {
					return nil, fmt.Errorf("reading out flag: %w", err)
				}

				expectNoChanges, err := s.Flags.GetBool("expect-no-changes")
				if err != nil {
					return nil, fmt.Errorf("reading expect-no-changes flag: %w", err)
				}

				orig, err := os.ReadFile(s.Path(infile))
				if err != nil {
					return nil, fmt.Errorf("reading %s: %w", infile, err)
				}

				obj, gvk, err := testutils.DecodeObjectGVK(orig)
				if err != nil {
					return nil, fmt.Errorf("decoding: %w", err)
				}

				objMeta, err := meta.Accessor(obj)
				if err != nil {
					return nil, fmt.Errorf("accessor: %w", err)
				}

				objRaw, err := runtime.Encode(unstructured.UnstructuredJSONScheme, obj)
				if err != nil {
					return nil, fmt.Errorf("encoding object: %w", err)
				}

				gvr, _ := meta.UnsafeGuessKindToResource(*gvk)
				req := admission_v1.AdmissionReview{
					Request: &admission_v1.AdmissionRequest{
						Resource:  metav1.GroupVersionResource(gvr),
						UID:       objMeta.GetUID(),
						Name:      objMeta.GetName(),
						Namespace: objMeta.GetNamespace(),
						Operation: op,
						Object: runtime.RawExtension{
							Object: obj, Raw: objRaw,
						},
					},
				}

				var buf bytes.Buffer
				err = unstructured.UnstructuredJSONScheme.Encode(&req, &buf)
				if err != nil {
					return nil, fmt.Errorf("encoding admission review: %w", err)
				}

				return func(s *script.State) (stdout string, stderr string, err error) {
					ctx, cancel := context.WithTimeout(s.Context(), timeout)
					defer cancel()

					httpreq, err := http.NewRequestWithContext(ctx, "POST",
						fmt.Sprintf("https://%s/%s", cfg.HostPort, strings.TrimLeft(reqpath, "/")), &buf)
					if err != nil {
						return "", "", fmt.Errorf("constructing the HTTP request: %w", err)
					}

					httpreq.Header.Set("Content-Type", "application/json")
					httpresp, err := client.Do(httpreq)
					if err != nil {
						// Override the error in case the root context is still valid,
						// but we hit the timeout, as otherwise the script engine treats
						// it as a failure, regardless of whether we use the "!" operator.
						if errors.Is(err, context.DeadlineExceeded) && s.Context().Err() == nil {
							return "", "", errors.New("timed out waiting for response")
						}

						return "", "", fmt.Errorf("http request: %w", err)
					}

					defer httpresp.Body.Close()
					raw, err := safeio.ReadAllLimit(httpresp.Body, safeio.MB)
					if err != nil {
						return "", "", fmt.Errorf("reading the response body: %w", err)
					}

					if httpresp.StatusCode != http.StatusOK {
						return "", string(raw), fmt.Errorf("unexpected status code %d", httpresp.StatusCode)
					}

					obj, _, err := admissionCodecs.UniversalDeserializer().Decode(raw, nil, &admission_v1.AdmissionReview{})
					if err != nil {
						return "", "", fmt.Errorf("decoding the response: %w", err)
					}

					resp, ok := obj.(*admission_v1.AdmissionReview)
					if !ok {
						return "", "", fmt.Errorf("decoding the response: unexpected type %T", obj)
					}

					if !resp.Response.Allowed {
						var reason = "unknown"
						if result := resp.Response.Result; result != nil {
							reason = string(result.Message)
						}

						return "", reason + "\n", fmt.Errorf("not allowed: %s", reason)
					}

					if expectNoChanges {
						if resp.Response.PatchType != nil {
							return "", string(resp.Response.Patch), errors.New("expected no patches, but got some")
						}

						return "", "", nil
					}

					var out = orig
					if ptr.Deref(resp.Response.PatchType, "") == admission_v1.PatchTypeJSONPatch {
						patch, err := jsonpatch.DecodePatch(resp.Response.Patch)
						if err != nil {
							return "", "", fmt.Errorf("parsing the patch: %w", err)
						}

						patched, err := patch.Apply(objRaw)
						if err != nil {
							return "", "", fmt.Errorf("applying the patch: %w", err)
						}

						obj, _, err = testutils.DecodeObjectGVK(patched)
						if err != nil {
							return "", "", fmt.Errorf("decoding the patched object: %w", err)
						}

						out, err = yaml.Marshal(obj)
						if err != nil {
							return "", "", fmt.Errorf("marshaling the patched object: %w", err)
						}
					}

					if outfile != "" {
						return "", "", os.WriteFile(s.Path(outfile), out, 0644)
					}

					return string(out), "", nil
				}, nil
			},
		),
	})
}

func (w *webhook) generateTLSPair(cfg whcfg.Config) error {
	if !cfg.Enabled {
		return nil
	}

	newPair := func(tmpl, parent *x509.Certificate, signer ed25519.PrivateKey) (ed25519.PrivateKey, []byte, error) {
		var reader = rand.Reader

		tmpl.NotBefore = time.Now().Add(-time.Minute)
		tmpl.NotAfter = time.Now().Add(60 * time.Minute)

		pub, priv, err := ed25519.GenerateKey(reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating key: %w", err)
		}

		if parent == nil {
			parent, signer = tmpl, priv
		}

		der, err := x509.CreateCertificate(reader, tmpl, parent, pub, signer)
		if err != nil {
			return nil, nil, fmt.Errorf("creating certificate: %w", err)
		}

		return priv, der, nil
	}

	cakey, cader, err := newPair(&x509.Certificate{
		Subject:               pkix.Name{Organization: []string{"Cilium Test CA"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}, nil, nil)
	if err != nil {
		return fmt.Errorf("CA cert: %w", err)
	}

	cacrt, err := x509.ParseCertificate(cader)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	w.root.AddCert(cacrt)

	key, der, err := newPair(&x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}, cacrt, cakey)
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}

	keyder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	if err = os.WriteFile(w.tlsKeyFile(), pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: keyder},
	), 0644); err != nil {
		return fmt.Errorf("writing tls.key: %w", err)
	}

	if err = os.WriteFile(w.tlsCertFile(), pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	), 0644); err != nil {
		return fmt.Errorf("writing tls.crt: %w", err)
	}

	return nil
}
