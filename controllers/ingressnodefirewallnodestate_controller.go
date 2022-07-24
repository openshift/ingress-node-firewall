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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	ingressnodefwv1alpha1 "ingress-node-firewall/api/v1alpha1"
)

// IngressNodeFirewallNodeStateReconciler reconciles a IngressNodeFirewallNodeState object
type IngressNodeFirewallNodeStateReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	NodeName  string
	Namespace string
}

//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,namespace=ingress-node-firewall,resources=ingressnodefirewallnodestates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,namespace=ingress-node-firewall,resources=ingressnodefirewallnodestates/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingress-nodefw.ingress-nodefw,namespace=ingress-node-firewall,resources=ingressnodefirewallnodestates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the IngressNodeFirewallNodeState object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallNodeStateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// This node's name and the NodeState's name must match. Also, the NodeState object must
	// have been created inside the correct namespce.
	// Otherwise, this request is not for us.
	if req.Name != r.NodeName || req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	nodeState := &ingressnodefwv1alpha1.IngressNodeFirewallNodeState{}
	err := r.Get(ctx, req.NamespacedName, nodeState)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			log.Info("IngressNodeFirewallNodeState resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get Memcached")
		return ctrl.Result{}, err
	}

	log.Info("Reconciling resource and programming bpf", "name", nodeState.Name, "namespace", nodeState.Namespace)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallNodeStateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewallNodeState{}).
		Complete(r)
}
