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
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ingressnodefwv1alpha1 "ingress-node-firewall/api/v1alpha1"
	"ingress-node-firewall/pkg/apply"
	"ingress-node-firewall/pkg/render"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultIngressNodeFirwallCrName = "ingressnodefirewallconfig"
	IngressNodeFirewallManifestPath = "./bindata/manifests/daemon"
)

var ManifestPath = IngressNodeFirewallManifestPath

// IngressNodeFirewallConfigReconciler reconciles a IngressNodeFirewallConfig object
type IngressNodeFirewallConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewallconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewallconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewallconfigs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IngressNodeFirewallConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	logger := r.Log.WithValues("ingress node firewall config", req.NamespacedName)

	instance := &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
	err := r.Get(context.TODO(), req.NamespacedName, instance)
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

	if req.Name != defaultIngressNodeFirwallCrName {
		logger.Error(err, "Invalid IngressNode firewall config resource name", "name", req.Name)
		return ctrl.Result{}, nil // Return success to avoid requeue
	}

	if err := r.syncIngressNodeFwConfigResources(instance); err != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewallConfig{}).
		Complete(r)
}

func (r *IngressNodeFirewallConfigReconciler) syncIngressNodeFwConfigResources(config *ingressnodefwv1alpha1.IngressNodeFirewallConfig) error {
	logger := r.Log.WithName("syncIngressNodeFirewallConfigResources")
	logger.Info("Start")
	data := render.MakeRenderData()

	data.Data["Image"] = os.Getenv("DAEMONSET_IMAGE")
	objs, err := render.RenderDir(ManifestPath, &data)
	if err != nil {
		logger.Error(err, "Fail to render config daemon manifests")
		return err
	}

	for _, obj := range objs {
		if obj.GetKind() == "DaemonSet" &&
			(len(config.Spec.NodeSelector) > 0 || len(config.Spec.Tolerations) > 0) {
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
			if len(config.Spec.Tolerations) > 0 {
				ds.Spec.Template.Spec.Tolerations = config.Spec.Tolerations
			}
			err = scheme.Convert(ds, obj, nil)
			if err != nil {
				logger.Error(err, "Fail to convert DaemonSet to IngressNodeFirewallConfig object")
				return err
			}
		}

		if err := apply.ApplyObject(context.TODO(), r.Client, obj); err != nil {
			return errors.Wrapf(err, "could not apply (%s) %s", obj.GroupVersionKind(), obj.GetName())
		}
	}
	return nil
}
