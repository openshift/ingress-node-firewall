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

package main

import (
	"crypto/tls"
	"flag"
	"os"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/controllers"
	"github.com/openshift/ingress-node-firewall/pkg/platform"
	"github.com/openshift/ingress-node-firewall/pkg/version"
	"github.com/openshift/ingress-node-firewall/pkg/webhook"

	//+kubebuilder:scaffold:imports

	bpfmaniov1alpha1 "github.com/bpfman/bpfman-operator/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookctrl "sigs.k8s.io/controller-runtime/pkg/webhook"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ingressnodefwv1alpha1.AddToScheme(scheme))
	utilruntime.Must(bpfmaniov1alpha1.Install(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var enableWebhook bool
	var probeAddr string
	var enableHTTP2 bool
	var secureMetrics bool
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":39201", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableWebhook, "enable-webhook", false, "Enable deployment of webhook to validate CR IngressNodeFirewall")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableHTTP2, "enable-http2", enableHTTP2, "If HTTP/2 should be enabled for the metrics and webhook servers.")
	flag.BoolVar(&secureMetrics, "metrics-secure", secureMetrics, "If the metrics endpoint should be served securely.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info("Version", "version.Version", version.Version)

	disableHTTP2 := func(c *tls.Config) {
		if enableHTTP2 {
			return
		}
		c.NextProtos = []string{"http/1.1"}
	}

	if _, ok := os.LookupEnv("DAEMONSET_IMAGE"); !ok {
		setupLog.Error(nil, "DAEMONSET_IMAGE env variable must be set")
		os.Exit(1)
	}
	nameSpace, ok := os.LookupEnv("DAEMONSET_NAMESPACE")
	if !ok {
		setupLog.Error(nil, "DAEMONSET_NAMESPACE env variable must be set")
		os.Exit(1)
	}
	if _, ok = os.LookupEnv("KUBE_RBAC_PROXY_IMAGE"); !ok {
		setupLog.Error(nil, "KUBE_RBAC_PROXY_IMAGE env variable must be set")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       []func(*tls.Config){disableHTTP2},
		},
		WebhookServer: webhookctrl.NewServer(webhookctrl.Options{
			Port:    9443,
			TLSOpts: []func(config *tls.Config){disableHTTP2},
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d902e78d.ingress-nodefw",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.IngressNodeFirewallReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Log:       ctrl.Log.WithName("controllers").WithName("IngressNodeFirewall"),
		Namespace: nameSpace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IngressNodeFirewall")
		os.Exit(1)
	}

	if enableWebhook {
		if err = (&webhook.IngressNodeFirewallWebhook{}).SetupWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "IngressNodeFirewall")
			os.Exit(1)
		}
	}

	cfg := ctrl.GetConfigOrDie()
	platformInfo, err := platform.GetPlatformInfo(cfg)
	if err != nil {
		setupLog.Error(err, "unable to get platform name")
		os.Exit(1)
	}
	if err = (&controllers.IngressNodeFirewallConfigReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Log:          ctrl.Log.WithName("controllers").WithName("IngressNodeFirewallConfig"),
		Namespace:    nameSpace,
		PlatformInfo: platformInfo,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IngressNodeFirewallConfig")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
