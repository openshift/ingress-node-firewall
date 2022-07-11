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
	nodefwloader "ingress-node-firewall/pkg/ebpf"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	ingressnodefwiov1alpha1 "ingress-node-firewall/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NodeEndpointReconciler reconciles a NodeEndpoint object
type NodeEndpointReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

//+kubebuilder:rbac:groups=ingress-nodefw.io.ingress-nodefw.io,resources=nodeendpoints,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingress-nodefw.io.ingress-nodefw.io,resources=nodeendpoints/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingress-nodefw.io.ingress-nodefw.io,resources=nodeendpoints/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *NodeEndpointReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	instance := &ingressnodefwiov1alpha1.NodeEndpoint{}
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

func (r *NodeEndpointReconciler) reconcileResource(ctx context.Context, req ctrl.Request, instance *ingressnodefwiov1alpha1.NodeEndpoint, isDelete bool) (ctrl.Result, error) {
	if err := r.syncIngressNodeEndPointResources(instance, isDelete); err != nil {
		return ctrl.Result{}, errors.Wrapf(err, "FailedToSyncIngressNodeEndPointResources")
	}
	return ctrl.Result{}, nil
}

func (r *NodeEndpointReconciler) syncIngressNodeEndPointResources(instance *ingressnodefwiov1alpha1.NodeEndpoint, isDelete bool) error {
	logger := r.Log.WithName("syncIngressNodeEndPointResources")
	logger.Info("Start")
	// HACK-POC: we can't attach the operator
	if err := nodefwloader.IngessNodeFwAttach(instance.Spec.Interfaces, isDelete); err != nil {
		logger.Error(err, "Fail to attach ingress node fw to %v", instance.Spec.Interfaces)
		return err
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeEndpointReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwiov1alpha1.NodeEndpoint{}).
		Complete(r)
}
