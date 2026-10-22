package ote

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	e2e "github.com/openshift/ingress-node-firewall/test/e2e"
)

var _ = g.Describe("[sig-network][OCPFeatureGate:TLSAdherence][Serial] TLS Profile Compliance - Ingress Node Firewall", func() {
	var (
		oc     *e2e.OCClient
		ctx    context.Context
		cancel context.CancelFunc
	)

	g.BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 90*time.Minute)
		oc = e2e.NewOCClient("")
		g.DeferCleanup(func() {
			if cancel != nil {
				cancel()
			}
		})
	})

	g.It("[JIRA:Networking][Level0] should verify TLS compliance across Modern and Intermediate profiles with different adherence policies", ote.Informing(), func() {
		isOpenShift, err := IsOpenShiftCluster(ctx, oc)
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to check if cluster is OpenShift")
		if !isOpenShift {
			g.Skip("TLS Profile Compliance testing requires OpenShift cluster with config.openshift.io APIs")
		}

		// Check if Ingress Node Firewall operator is installed
		if !isINFWOperatorInstalled(ctx, oc) {
			g.Skip("Ingress Node Firewall operator is not installed - skipping TLS compliance test")
		}

		// Ensure IngressNodeFirewallConfig exists before testing (silently create)
		createINFWConfig(ctx, oc)
		g.DeferCleanup(func() { deleteINFWConfig(ctx, oc) })

		// Scenario 1: Modern TLS Profile with LegacyAdheringComponentsOnly
		g.By("Configuring and verifying Modern TLS Profile with LegacyAdheringComponentsOnly")
		err = ConfigureTLSProfileWithAdherence(ctx, oc, configv1.TLSProfileModernType, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly)
		if IsTLSAdherenceNotSupported(err) {
			g.Skip(fmt.Sprintf("Skipping test - tlsAdherence API field not supported in this cluster version: %s", err.Error()))
		}
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to configure Modern TLS profile with LegacyAdheringComponentsOnly")
		verifyIngressNodeFirewallCompliance(ctx, oc)

		// Scenario 2: Modern TLS Profile with StrictAllComponents
		g.By("Configuring and verifying Modern TLS Profile with StrictAllComponents")
		err = ConfigureTLSProfileWithAdherence(ctx, oc, configv1.TLSProfileModernType, configv1.TLSAdherencePolicyStrictAllComponents)
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to configure Modern TLS profile with StrictAllComponents")
		verifyIngressNodeFirewallCompliance(ctx, oc)

		// Scenario 3: Intermediate TLS Profile with StrictAllComponents
		g.By("Configuring and verifying Intermediate TLS Profile with StrictAllComponents")
		err = ConfigureTLSProfileWithAdherence(ctx, oc, configv1.TLSProfileIntermediateType, configv1.TLSAdherencePolicyStrictAllComponents)
		o.Expect(err).NotTo(o.HaveOccurred(), "Failed to configure Intermediate TLS profile with StrictAllComponents")
		verifyIngressNodeFirewallCompliance(ctx, oc)
	})
})

func verifyIngressNodeFirewallCompliance(ctx context.Context, oc *e2e.OCClient) {
	g.By("Testing TLS compliance for ingress-node-firewall-daemon in openshift-ingress-node-firewall (port 9301)")
	err := VerifyIngressNodeFirewallTLSComplianceInPod(ctx, oc, opNamespace, "app=ingress-node-firewall-daemon")
	o.Expect(err).NotTo(o.HaveOccurred(), "TLS compliance verification failed for ingress-node-firewall-daemon")
}
