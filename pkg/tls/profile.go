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

package tls

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Profile struct {
	TLSOpts     []func(*tls.Config)
	profileSpec *configv1.TLSProfileSpec
	adherence   configv1.TLSAdherencePolicy
}

func GetProfileInfo(ctx context.Context, client ctrlclient.Client) (Profile, error) {
	log := logr.FromContextOrDiscard(ctx)

	// Fetch the API Server configuration to get both TLS profile and adherence policy
	apiServer := &configv1.APIServer{}
	if err := client.Get(ctx, types.NamespacedName{Name: openshifttls.APIServerName}, apiServer); err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			log.Info("OpenShift TLS profile API not available")
			return Profile{}, nil
		}

		return Profile{}, fmt.Errorf("failed to fetch apiserver.config.openshift.io/%s: %w", openshifttls.APIServerName, err)
	}

	profileSpec, err := openshifttls.GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return Profile{}, fmt.Errorf("failed to get TLS profile spec: %w", err)
	}

	profile := Profile{
		profileSpec: &profileSpec,
		adherence:   apiServer.Spec.TLSAdherence,
	}

	// Only apply TLS config if we should honor the cluster TLS profile
	// ShouldHonorClusterTLSProfile logic inlined (was removed from library-go):
	// Returns false for NoOpinion or LegacyAdheringComponentsOnly, true otherwise
	shouldHonor := !(apiServer.Spec.TLSAdherence == configv1.TLSAdherencePolicyNoOpinion ||
		apiServer.Spec.TLSAdherence == configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly)
	if !shouldHonor {
		log.Info("Not honoring TLS profile due to adherence policy", "adherence", apiServer.Spec.TLSAdherence)
		return profile, nil
	}

	// Convert profile spec to tls.Config using official OpenShift package
	tlsConfigFunc, unsupportedCiphers := openshifttls.NewTLSConfigFromProfile(profileSpec)

	// Log warnings for any unsupported ciphers
	for _, cipher := range unsupportedCiphers {
		log.Info("Cipher suite not available in this Go version, skipping", "cipher", cipher)
	}

	profile.TLSOpts = []func(*tls.Config){tlsConfigFunc}
	return profile, nil
}

func (p *Profile) SetupProfileWatch(ctx context.Context, mgr ctrl.Manager, onChange func()) error {
	log := logr.FromContextOrDiscard(ctx)

	if p.profileSpec == nil {
		return nil
	}

	tlsProfileWatcher := &openshifttls.SecurityProfileWatcher{
		Client:                    mgr.GetClient(),
		InitialTLSProfileSpec:     *p.profileSpec,
		InitialTLSAdherencePolicy: p.adherence,
		OnProfileChange: func(_ context.Context, oldProfile, newProfile configv1.TLSProfileSpec) {
			log.Info(fmt.Sprintf("TLS security profile changed. Old: MinVersion=%s Ciphers=%d, New: MinVersion=%s Ciphers=%d",
				oldProfile.MinTLSVersion, len(oldProfile.Ciphers), newProfile.MinTLSVersion, len(newProfile.Ciphers)))
			onChange()
		},
		OnAdherencePolicyChange: func(_ context.Context, oldTLSAdherencePolicy, newTLSAdherencePolicy configv1.TLSAdherencePolicy) {
			log.Info(fmt.Sprintf("TLS Adherence policy changed. Old: %s, New: %s", oldTLSAdherencePolicy, newTLSAdherencePolicy))
			onChange()
		},
	}

	if err := tlsProfileWatcher.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup TLS profile watcher: %w", err)
	}

	return nil
}

// GetProfileSpec returns the TLS profile spec, or nil if not honoring the cluster TLS profile.
func (p *Profile) GetProfileSpec() *configv1.TLSProfileSpec {
	// ShouldHonorClusterTLSProfile logic inlined (was removed from library-go):
	// Returns false for NoOpinion or LegacyAdheringComponentsOnly, true otherwise
	shouldHonor := !(p.adherence == configv1.TLSAdherencePolicyNoOpinion ||
		p.adherence == configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly)
	if !shouldHonor {
		return nil
	}
	return p.profileSpec
}

// ConvertCiphersToIANA converts a list of cipher suites from OpenSSL names to IANA names.
// OpenShift TLS profiles use OpenSSL cipher names, but Go's crypto/tls and kube-rbac-proxy
// expect IANA names.
func ConvertCiphersToIANA(ciphers []string) []string {
	validCiphers := make([]string, 0, len(ciphers))
	for _, cipher := range ciphers {
		// First try as IANA name directly.
		if _, err := crypto.CipherSuite(cipher); err == nil {
			validCiphers = append(validCiphers, cipher)
			continue
		}

		// Try converting from OpenSSL name to IANA name.
		ianaCiphers := crypto.OpenSSLToIANACipherSuites([]string{cipher})
		if len(ianaCiphers) == 1 {
			validCiphers = append(validCiphers, ianaCiphers[0])
		}
	}

	return validCiphers
}
