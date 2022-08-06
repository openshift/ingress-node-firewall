/*
Copyright 2022.

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

package controllers

import (
	"context"
	"log"
	"os"
	"testing"

	//+kubebuilder:scaffold:imports
	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	IngressNodeFwConfigTestNameSpace    = "ingress-node-fw-config-test-namespace"
	IngressNodeFirewallManifestPathTest = "../bindata/manifests/daemon"
	DeamonSetName                       = "ingress-node-firewall-daemon"
	IngressNodeFirewallResourceName     = "ingressnodefirewallconfig"
	daemonReconcilerNodeName            = "worker-daemon"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	By("Setting Ingress nodefirewall config environment variables")
	Expect(os.Setenv("DAEMONSET_IMAGE", "test-daemon:latest")).To(Succeed())
	Expect(os.Setenv("KUBE_RBAC_PROXY_IMAGE", "kube-rbac-proxy:latest")).To(Succeed())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = ingressnodefwv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	testNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: IngressNodeFwConfigTestNameSpace,
		},
	}

	err = k8sClient.Create(context.Background(), testNamespace)
	Expect(err).ToNot(HaveOccurred())

	ManifestPath = IngressNodeFirewallManifestPathTest

	err = (&IngressNodeFirewallConfigReconciler{
		Client:    k8sClient,
		Scheme:    scheme.Scheme,
		Log:       ctrl.Log.WithName("controllers").WithName("IngressNodeFirewallConfig"),
		Namespace: IngressNodeFwConfigTestNameSpace,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&IngressNodeFirewallReconciler{
		Client:    k8sClient,
		Scheme:    scheme.Scheme,
		Log:       ctrl.Log.WithName("controllers").WithName("IngressNodeFirewall"),
		Namespace: IngressNodeFwConfigTestNameSpace,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&IngressNodeFirewallNodeStateReconciler{
		Client:    k8sClient,
		Scheme:    scheme.Scheme,
		Log:       ctrl.Log.WithName("controllers").WithName("IngressNodeFirewall"),
		NodeName:  daemonReconcilerNodeName,
		Namespace: IngressNodeFwConfigTestNameSpace,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	ManifestPath = IngressNodeFirewallManifestPath
	if err := testEnv.Stop(); err != nil {
		log.Printf("failed to shut down testEnv err %v", err)
	}
})
