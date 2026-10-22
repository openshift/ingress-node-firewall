/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls_test

import (
	"context"
	"crypto/tls"
	"os"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	inftls "github.com/openshift/ingress-node-firewall/pkg/tls"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	_ = Describe("GetProfileInfo", testGetProfileInfo)
	_ = Describe("SetupProfileWatch", testSetupProfileWatch)
	_ = Describe("ConvertCiphersToIANA", testConvertCiphersToIANA)
)

func testGetProfileInfo() {
	t := newTestDriver()

	applyTLSOpts := func(opts []func(*tls.Config)) *tls.Config {
		tlsConfig := &tls.Config{}
		for _, f := range opts {
			f(tlsConfig)
		}

		return tlsConfig
	}

	Context("with Intermediate TLS profile", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileIntermediateType
		})

		It("should return a profile with MinVersion TLS 1.2", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.GetProfileSpec()).NotTo(BeNil())
			Expect(profile.GetProfileSpec().MinTLSVersion).To(Equal(configv1.VersionTLS12))
			Expect(profile.GetProfileSpec().Ciphers).To(Equal(configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsConfig.CipherSuites).NotTo(BeEmpty())
		})
	})

	Context("with Modern TLS profile (TLS 1.3)", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileModernType
		})

		It("should return a profile with MinVersion TLS 1.3 and no CipherSuites", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.GetProfileSpec()).To(Equal(configv1.TLSProfiles[configv1.TLSProfileModernType]))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(tlsConfig.CipherSuites).To(BeEmpty())
		})
	})

	Context("with Custom TLS profile", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS11,
						Ciphers: []string{
							"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
							"ECDHE-RSA-AES128-GCM-SHA256",
							"Unknown",
						},
					},
				},
			}
		})

		It("should return a valid profile with the custom settings", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.GetProfileSpec()).To(Equal(&t.apiServer.Spec.TLSSecurityProfile.Custom.TLSProfileSpec))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS11)))
			Expect(tlsConfig.CipherSuites).To(HaveLen(2))
		})
	})

	Context("with Custom TLS profile including Groups", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
							"TLS_AES_256_GCM_SHA384",
						},
						Groups: []configv1.TLSGroup{
							configv1.TLSGroupSecP256r1,
							configv1.TLSGroupSecP384r1,
						},
					},
				},
			}
		})

		It("should return a profile with CurvePreferences set correctly", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.GetProfileSpec()).To(Equal(&t.apiServer.Spec.TLSSecurityProfile.Custom.TLSProfileSpec))
			Expect(profile.GetProfileSpec().Groups).To(Equal([]configv1.TLSGroup{
				configv1.TLSGroupSecP256r1,
				configv1.TLSGroupSecP384r1,
			}))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsConfig.CipherSuites).To(HaveLen(2))
			// Verify CurvePreferences is set
			Expect(tlsConfig.CurvePreferences).NotTo(BeEmpty())
			Expect(tlsConfig.CurvePreferences).To(ContainElements(tls.CurveP256, tls.CurveP384))
		})
	})

	Context("with Custom TLS profile including all supported Groups", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS13,
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
							"TLS_AES_256_GCM_SHA384",
						},
						Groups: []configv1.TLSGroup{
							configv1.TLSGroupX25519,
							configv1.TLSGroupSecP256r1,
							configv1.TLSGroupSecP384r1,
							configv1.TLSGroupSecP521r1,
							configv1.TLSGroupX25519MLKEM768,
							configv1.TLSGroupSecP256r1MLKEM768,
							configv1.TLSGroupSecP384r1MLKEM1024,
						},
					},
				},
			}
		})

		It("should support all groups including post-quantum hybrids", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.GetProfileSpec()).To(Equal(&t.apiServer.Spec.TLSSecurityProfile.Custom.TLSProfileSpec))
			Expect(profile.GetProfileSpec().Groups).To(HaveLen(7))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			// TLS 1.3 cipher suites are handled differently, may be empty in config

			// Verify all curves are set including post-quantum hybrids
			Expect(tlsConfig.CurvePreferences).NotTo(BeEmpty())
			Expect(tlsConfig.CurvePreferences).To(ContainElements(
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.X25519MLKEM768,
				tls.SecP256r1MLKEM768,
				tls.SecP384r1MLKEM1024,
			))
			Expect(tlsConfig.CurvePreferences).To(HaveLen(7))
		})
	})

	Context("with tlsAdherence set to LegacyAdheringComponentsOnly", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileModernType
			t.apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
		})

		It("should return a profile with nil ProfileSpec and empty TLSOpts", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).NotTo(HaveOccurred())

			Expect(profile.GetProfileSpec()).To(BeNil())
			Expect(profile.TLSOpts).To(BeEmpty())
		})
	})

	When("the APIServer resource does not exist", func() {
		BeforeEach(func() {
			t.apiServer = nil
		})

		It("should return an empty profile", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).NotTo(HaveOccurred())

			Expect(profile.GetProfileSpec()).To(BeNil())
			Expect(profile.TLSOpts).To(BeEmpty())
		})
	})

	When("the APIServer resource retrieval fails", func() {
		BeforeEach(func() {
			t.tlsClient = fake.NewClientBuilder().
				WithScheme(t.clientScheme).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
						return apierrors.NewServiceUnavailable("mock error")
					},
				}).
				Build()
		})

		It("should return an error", func() {
			_, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).To(HaveOccurred())
		})
	})
}

func testSetupProfileWatch() {
	t := newTestDriver()

	var fakeMgr *FakeManager

	JustBeforeEach(func() {
		mgr, err := ctrl.NewManager(&rest.Config{}, ctrl.Options{
			Scheme: t.clientScheme,
			Metrics: server.Options{
				BindAddress: "0",
			},
			Controller: ctrlconfig.Controller{
				SkipNameValidation: ptr.To(true),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		fakeMgr = &FakeManager{
			Manager: mgr,
		}

		// Create fake client with interceptor that triggers reconciliation on APIServer updates.
		fakeMgr.client = fake.NewClientBuilder().
			WithScheme(t.clientScheme).
			WithObjects(t.apiServer).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if err := client.Update(ctx, obj, opts...); err != nil {
						return err
					}

					if apiServer, ok := obj.(*configv1.APIServer); ok {
						fakeMgr.triggerReconcile(ctx, apiServer)
					}

					return nil
				},
			}).Build()
	})

	testAPIServerUpdate := func(modify func(*configv1.APIServer)) {
		ctx, cancel := context.WithCancel(newLogContext())
		defer cancel()

		profile, err := inftls.GetProfileInfo(ctx, fakeMgr.client)
		Expect(err).NotTo(HaveOccurred())

		Expect(profile.SetupProfileWatch(ctx, fakeMgr, cancel)).To(Succeed())

		// Update the APIServer object to change the TLS profile to Modern
		apiServer := &configv1.APIServer{}
		Expect(fakeMgr.client.Get(ctx, client.ObjectKey{Name: openshifttls.APIServerName}, apiServer)).To(Succeed())

		modify(apiServer)

		Expect(fakeMgr.client.Update(ctx, apiServer)).To(Succeed())

		// Wait for the context to be canceled
		Eventually(ctx.Done()).Within(2 * time.Second).Should(BeClosed())
	}

	When("the TLS profile changes", func() {
		It("should invoke onChange", func() {
			testAPIServerUpdate(func(apiServer *configv1.APIServer) {
				apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileModernType,
				}
			})
		})
	})

	When("TLS adherence changes", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
		})

		It("should invoke onChange", func() {
			testAPIServerUpdate(func(apiServer *configv1.APIServer) {
				apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyStrictAllComponents
			})
		})
	})
}

type testDriver struct {
	tlsClient    client.Client
	clientScheme *runtime.Scheme
	apiServer    *configv1.APIServer
}

func newTestDriver() *testDriver {
	t := &testDriver{}

	BeforeEach(func() {
		t.apiServer = &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{
				Name: openshifttls.APIServerName,
			},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{},
				TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}

		t.clientScheme = runtime.NewScheme()
		utilruntime.Must(k8sscheme.AddToScheme(t.clientScheme))
		utilruntime.Must(configv1.Install(t.clientScheme))

		t.tlsClient = fake.NewClientBuilder().WithScheme(t.clientScheme).Build()
	})

	JustBeforeEach(func() {
		if t.apiServer != nil {
			Expect(t.tlsClient.Create(context.TODO(), t.apiServer)).To(Succeed())
		}
	})

	return t
}

type FakeManager struct {
	manager.Manager
	client     client.Client
	reconciler reconcile.Reconciler
}

func (f *FakeManager) GetClient() client.Client {
	return f.client
}

// Add captures reconcilers so we can trigger them manually
func (f *FakeManager) Add(runnable manager.Runnable) error {
	if r, ok := runnable.(reconcile.Reconciler); ok {
		f.reconciler = r
	}

	return f.Manager.Add(runnable)
}

func (f *FakeManager) triggerReconcile(ctx context.Context, apiServer *configv1.APIServer) {
	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Name: apiServer.Name,
		},
	}

	go func(r reconcile.Reconciler) {
		defer GinkgoRecover()
		Expect(r).NotTo(BeNil(), "reconciler must be registered before triggerReconcile")
		_, err := r.Reconcile(ctx, req)
		Expect(err).NotTo(HaveOccurred())
	}(f.reconciler)
}

func newLogContext() context.Context {
	return logr.NewContext(context.TODO(), zap.New(zap.WriteTo(os.Stdout), zap.UseDevMode(true)))
}

func testConvertCiphersToIANA() {
	It("should convert OpenSSL cipher names to IANA names", func() {
		input := []string{
			"TLS_AES_128_GCM_SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"TLS_AES_256_GCM_SHA384",
			"ECDHE-RSA-CHACHA20-POLY1305",
		}
		Expect(inftls.ConvertCiphersToIANA(input)).To(Equal([]string{
			"TLS_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		}))
	})
}
