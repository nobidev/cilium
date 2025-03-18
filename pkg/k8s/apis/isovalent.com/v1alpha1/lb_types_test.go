// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLBService_AllReferencedTLSCertificateSecretNames(t *testing.T) {
	testCases := []struct {
		desc    string
		service *LBService
		secrets []string
	}{
		{
			desc: "HTTPS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
		{
			desc: "TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
		{
			desc: "HTTPS Proxy & TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-3"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2", "tls-3"},
		},
		{
			desc: "HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
		{
			desc: "TLS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy TLS Cert & CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			assert.Equal(t, tC.secrets, tC.service.AllReferencedTLSCertificateSecretNames())
		})
	}
}

func TestLBService_AllReferencedTLSCACertValidationSecretNames(t *testing.T) {
	testCases := []struct {
		desc    string
		service *LBService
		secrets []string
	}{
		{
			desc: "HTTPS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{},
		},
		{
			desc: "TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{},
		},
		{
			desc: "HTTPS Proxy & TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-3"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{},
		},
		{
			desc: "HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1"},
		},
		{
			desc: "TLS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1"},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1"},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy TLS Cert & CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1", "ca-cert-2"},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			assert.Equal(t, tC.secrets, tC.service.AllReferencedTLSCACertValidationSecretNames())
		})
	}
}

func TestLBService_AllReferencedSecretNames(t *testing.T) {
	testCases := []struct {
		desc    string
		service *LBService
		secrets []string
	}{
		{
			desc: "HTTPS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
		{
			desc: "TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2"},
		},
		{
			desc: "HTTPS Proxy & TLS Proxy TLS certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-3"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
					},
				},
			}}},
			secrets: []string{"tls-1", "tls-2", "tls-3"},
		},
		{
			desc: "HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1", "tls-1", "tls-2"},
		},
		{
			desc: "TLS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1"},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1"},
		},
		{
			desc: "TLS Proxy & HTTPS Proxy TLS Cert & CA Cert validation certificates ordered and unique",
			service: &LBService{Spec: LBServiceSpec{Applications: LBServiceApplications{
				HTTPSProxy: &LBServiceApplicationHTTPSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-1"},
						},
					},
				},
				TLSProxy: &LBServiceApplicationTLSProxy{
					TLSConfig: LBServiceTLSConfig{
						Certificates: []LBServiceTLSCertificate{
							{SecretRef: LBServiceSecretRef{Name: "tls-2"}},
							{SecretRef: LBServiceSecretRef{Name: "tls-1"}},
						},
						Validation: &LBTLSValidationConfig{
							SecretRef: LBServiceSecretRef{Name: "ca-cert-2"},
						},
					},
				},
			}}},
			secrets: []string{"ca-cert-1", "ca-cert-2", "tls-1", "tls-2"},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			assert.Equal(t, tC.secrets, tC.service.AllReferencedSecretNames())
		})
	}
}
