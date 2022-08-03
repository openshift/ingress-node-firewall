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
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	ingressnodefwiov1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/controllers"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"
	"github.com/openshift/ingress-node-firewall/pkg/version"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(ingressnodefwiov1alpha1.AddToScheme(scheme))
	utilruntime.Must(ingressnodefwv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var probeAddr string
	// We are host networked, we set default to loopback by default
	flag.StringVar(&probeAddr, "health-probe-bind-address", "127.0.0.1:39300", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", "127.0.0.1:39301", "The address the metric endpoint binds to.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	setupLog.Info("Version", "version.Version", version.Version)

	nodeName, ok := os.LookupEnv("NODE_NAME")
	if !ok {
		setupLog.Error(nil, "NODE_NAME env variable must be set")
		os.Exit(1)
	}
	namespace, ok := os.LookupEnv("NAMESPACE")
	if !ok {
		setupLog.Error(nil, "NAMESPACE env variable must be set")
		os.Exit(1)
	}

	pollPeriod, ok := os.LookupEnv("POLL_PERIOD_SECONDS")
	if !ok {
		setupLog.Error(nil, "POLL_PERIOD_SECONDS env variable must be set")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         false,
		Namespace:              namespace,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	stats, err := metrics.NewStatistics(pollPeriod)
	if err != nil {
		setupLog.Error(err, "unable to create new metrics")
		os.Exit(1)
	}
	stats.Register()
	defer stats.StopPoll()

	if err = (&controllers.IngressNodeFirewallNodeStateReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		NodeName:  nodeName,
		Namespace: namespace,
		Log:       ctrl.Log.WithName("controllers").WithName("IngressNodeFirewall"),
		Stats:     stats,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IngressNodeFirewallNodeState")
		os.Exit(1)
	}

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
