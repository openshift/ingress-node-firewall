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

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	nodefwloader "github.com/openshift/ingress-node-firewall/pkg/ebpf"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IngressNodeFirewallReconciler reconciles a IngressNodeFirewall object
type IngressNodeFirewallReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewalls,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewalls/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,resources=ingressnodefirewalls/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	instance := &ingressnodefwv1alpha1.IngressNodeFirewall{}
	err := r.Get(context.TODO(), req.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return r.reconcileResource(ctx, req, instance, true)
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return r.reconcileResource(ctx, req, instance, false)
}

func (r *IngressNodeFirewallReconciler) reconcileResource(ctx context.Context, req ctrl.Request, instance *ingressnodefwv1alpha1.IngressNodeFirewall, isDelete bool) (ctrl.Result, error) {
	if err := r.syncIngressNodeFirewallResources(instance, isDelete); err != nil {
		return ctrl.Result{}, errors.Wrapf(err, "FailedToSyncIngressNodeFirewallResources")
	}
	return ctrl.Result{}, nil
}

func (r *IngressNodeFirewallReconciler) syncIngressNodeFirewallResources(instance *ingressnodefwv1alpha1.IngressNodeFirewall, isDelete bool) error {
	logger := r.Log.WithName("syncIngressNodeFirewallResources")
	logger.Info("Start")

	c, err := nodefwloader.NewIngNodeFwController()
	if err != nil {
		logger.Error(err, "Fail to create nodefw controller instance %s", err)
		return err
	}

	// HACK-POC: we can't load bpf rules from the operator
	for _, rule := range instance.Spec.Ingress {
		if err := c.IngressNodeFwRulesLoader(rule, isDelete); err != nil {
			logger.Error(err, "Fail to load ingress firewall rule %v", rule)
			return err
		}
	}

	if err := c.IngressNodeFwAttach(*instance.Spec.Interfaces, isDelete); err != nil {
		logger.Error(err, "Fail to attach ingress firewall prog %s", err)
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewall{}).
		Complete(r)
}
