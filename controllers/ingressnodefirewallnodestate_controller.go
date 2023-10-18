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

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/ebpfsyncer"
	"github.com/openshift/ingress-node-firewall/pkg/metrics"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// IngressNodeFirewallNodeStateReconciler reconciles a IngressNodeFirewallNodeState object
type IngressNodeFirewallNodeStateReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	NodeName  string
	Namespace string
	Log       logr.Logger
	Stats     *metrics.Statistics
}

var ingressNodeFirewallFinalizer = "ingressnodefirewall.openshift.io/finalizer"

//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallnodestates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,namespace=ingress-node-firewall-system,resources=ingressnodefirewallnodestates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,namespace=ingress-node-firewall-system,resources=ingressnodefirewallnodestates/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,namespace=ingress-node-firewall-system,resources=ingressnodefirewallnodestates/finalizers,verbs=update

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
	// This node's name and the NodeState's name must match. Also, the NodeState object must
	// have been created inside the correct namespace.
	// Otherwise, this request is not for us.
	if req.Name != r.NodeName || req.Namespace != r.Namespace {
		return ctrl.Result{}, nil
	}
	nodeState := &infv1alpha1.IngressNodeFirewallNodeState{}
	err := r.Get(ctx, req.NamespacedName, nodeState)
	if err != nil {
		// Expect not to find node state that has been deleted. Handling of deletion should have previously occurred,
		// therefore we only ignore errors with reason 'StatusReasonNotFound'.
		if !apierrors.IsNotFound(err) {
			r.Log.Error(err, "unable to get IngressNodeFirewallNodeState")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// check if node state is being deleted
	if isNodeStateDeletionInProgress(nodeState) {
		if controllerutil.ContainsFinalizer(nodeState, ingressNodeFirewallFinalizer) {
			if result, err := r.reconcileResource(ctx, nodeState, true); err != nil {
				r.Log.Error(err, "failed to reconcile IngressNodeFirewallNodeState that is being deleted")
				return result, err
			}
			controllerutil.RemoveFinalizer(nodeState, ingressNodeFirewallFinalizer)
			if err = r.Update(ctx, nodeState); err != nil {
				return ctrl.Result{}, err
			}
		}
		// stop reconciliation as node state is being deleted
		return ctrl.Result{}, nil
	} else {
		// ensure node state contains finalizer if object is not being deleted
		if !controllerutil.ContainsFinalizer(nodeState, ingressNodeFirewallFinalizer) {
			controllerutil.AddFinalizer(nodeState, ingressNodeFirewallFinalizer)
			if err = r.Update(ctx, nodeState); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	r.Log.Info("Reconciling resource and programming bpf", "name", nodeState.Name, "namespace", nodeState.Namespace)
	return r.reconcileResource(ctx, nodeState, false)
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallNodeStateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infv1alpha1.IngressNodeFirewallNodeState{}).
		Complete(r)
}

// mock shall be nil for production but can be overwritten for mock tests.
var mock ebpfsyncer.EbpfSyncer = nil

// reconcileResource reconciles the resource by getting the EbpfDaemon singleton's SyncInterfaceIngressRules method.
// For mock tests, var mock can be overwritten.
func (r *IngressNodeFirewallNodeStateReconciler) reconcileResource(
	ctx context.Context, instance *infv1alpha1.IngressNodeFirewallNodeState, isDelete bool) (ctrl.Result, error) {
	if err := ebpfsyncer.GetEbpfSyncer(ctx, r.Log, r.Stats, mock).SyncInterfaceIngressRules(instance.Spec.InterfaceIngressRules, isDelete); err != nil {
		return ctrl.Result{}, errors.Wrapf(err, "FailedToSyncIngressNodeFirewallResources")
	}
	return ctrl.Result{}, nil
}

func isNodeStateDeletionInProgress(nodeState *infv1alpha1.IngressNodeFirewallNodeState) bool {
	return !nodeState.ObjectMeta.DeletionTimestamp.IsZero()
}
