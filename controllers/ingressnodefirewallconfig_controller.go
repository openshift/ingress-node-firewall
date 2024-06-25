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
	"os"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/apply"
	"github.com/openshift/ingress-node-firewall/pkg/platform"
	"github.com/openshift/ingress-node-firewall/pkg/render"
	"github.com/openshift/ingress-node-firewall/pkg/status"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultIngressNodeFirewallCrName = "ingressnodefirewallconfig"
	IngressNodeFirewallManifestPath  = "./bindata/manifests/daemon"
)

var ManifestPath = IngressNodeFirewallManifestPath

// IngressNodeFirewallConfigReconciler reconciles a IngressNodeFirewallConfig object
type IngressNodeFirewallConfigReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Log          logr.Logger
	Namespace    string
	PlatformInfo platform.PlatformInfo
}

// +kubebuilder:rbac:groups=apps,namespace=ingress-node-firewall-system,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the IngressNodeFirewallConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	errorMsg, wrappedErrMsg, condition := "", "", ""
	var ctrResult = ctrl.Result{}
	logger := r.Log.WithValues("ingress node firewall config", req.NamespacedName)
	req.Namespace = r.Namespace
	instance := &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if req.Name != defaultIngressNodeFirewallCrName {
		logger.Error(err, "Invalid IngressNode firewall config resource name", "name", req.Name)
		return ctrl.Result{}, nil // Return success to avoid requeue
	}

	if err = r.syncIngressNodeFwConfigResources(ctx, instance); err != nil {
		condition = status.ConditionDegraded
		err = errors.Wrapf(err, "FailedToSyncIngressNodeFirewallConfigResources")
	} else {
		err = status.IsIngressNodeFirewallConfigAvailable(ctx, r.Client, req.NamespacedName.Namespace)
		if err != nil {
			if _, ok := err.(status.IngressNodeFirewallConfigResourcesNotReadyError); ok {
				ctrResult = ctrl.Result{RequeueAfter: 5 * time.Second}
			}
			condition = status.ConditionProgressing
		} else {
			condition = status.ConditionAvailable
		}
	}

	if err != nil {
		errorMsg = err.Error()
		if errors.Unwrap(err) != nil {
			wrappedErrMsg = errors.Unwrap(err).Error()
		}
	}
	if err = status.Update(context.TODO(), r.Client, instance, condition, errorMsg, wrappedErrMsg); err != nil {
		logger.Info("failed to update ingress node firewall config status", "Desired status", status.ConditionAvailable)
		err = nil
	}
	return ctrResult, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewallConfig{}).
		Owns(&appsv1.DaemonSet{}).
		Complete(r)
}

func (r *IngressNodeFirewallConfigReconciler) syncIngressNodeFwConfigResources(ctx context.Context, config *ingressnodefwv1alpha1.IngressNodeFirewallConfig) error {
	logger := r.Log.WithName("syncIngressNodeFirewallConfigResources")
	logger.Info("Start")
	data := render.MakeRenderData()

	data.Data["Image"] = os.Getenv("DAEMONSET_IMAGE")
	data.Data["NameSpace"] = r.Namespace
	data.Data["RBACProxyImage"] = os.Getenv("KUBE_RBAC_PROXY_IMAGE")
	data.Data["IsOpenShift"] = r.PlatformInfo.IsOpenShift()
	if config.Spec.Debug != nil {
		data.Data["Debug"] = "0"
		if *config.Spec.Debug {
			data.Data["Debug"] = "1"
		}
	}

	if config.Spec.EBPFProgramManagerMode != nil {
		data.Data["Mode"] = "0"
		if *config.Spec.EBPFProgramManagerMode {
			data.Data["Mode"] = "1"
		}
	}

	objs, err := render.RenderDir(ManifestPath, &data)
	if err != nil {
		logger.Error(err, "Fail to render config daemon manifests")
		return err
	}

	for _, obj := range objs {
		if obj.GetKind() == "DaemonSet" {
			scheme := kscheme.Scheme
			ds := &appsv1.DaemonSet{}
			err = scheme.Convert(obj, ds, nil)
			if err != nil {
				logger.Error(err, "Fail to convert IngressNodeFirewallConfig object to DaemonSet")
				return err
			}
			if len(config.Spec.NodeSelector) > 0 {
				ds.Spec.Template.Spec.NodeSelector = config.Spec.NodeSelector
			}
			if err := ctrl.SetControllerReference(config, ds, r.Scheme); err != nil {
				return errors.Wrapf(err, "Failed to set controller reference to %s %s", obj.GetNamespace(), obj.GetName())
			}
			err = scheme.Convert(ds, obj, nil)
			if err != nil {
				logger.Error(err, "Fail to convert DaemonSet to IngressNodeFirewallConfig object")
				return err
			}

			if err := apply.ApplyObject(ctx, r.Client, obj); err != nil {
				return errors.Wrapf(err, "could not apply (%s) %s", obj.GroupVersionKind(), obj.GetName())
			}
		}
	}
	return nil
}
