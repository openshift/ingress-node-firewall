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

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// IngressNodeFirewallReconciler reconciles a IngressNodeFirewall object
type IngressNodeFirewallReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Log       logr.Logger
	Namespace string
}

//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewalls,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewalls/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewalls/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// 1) Get all IngressNodeFirewall objects (cluster scoped) and build the nodeStateSpecs.
	//    nodeStateSpec is a map[<nodeName>]<IngressNodeFirewallNodeStateSpec>.
	ingressNodeFirewallList := &infv1alpha1.IngressNodeFirewallList{}
	if err := r.List(ctx, ingressNodeFirewallList); err != nil {
		r.Log.Error(err, "Failed to list IngressNodeFirewall objects")
		return ctrl.Result{}, err
	}
	nodeStateDesiredSpecs, err := r.buildNodeStateSpecs(ctx, ingressNodeFirewallList)
	if err != nil {
		r.Log.Error(err, "Failed to build IngressNodeFirewallNodeState")
		return ctrl.Result{}, err
	}

	// 2) Get all IngressNodeFirewallNodeState objects in namespace <namespace> (namespace scoped).
	ingressNodeFirewallNodeStateList := infv1alpha1.IngressNodeFirewallNodeStateList{}
	listOpts := []client.ListOption{
		client.InNamespace(r.Namespace),
	}
	if err := r.List(ctx, &ingressNodeFirewallNodeStateList, listOpts...); err != nil {
		r.Log.Error(err, "Failed to list ingress node firewalls")
		return ctrl.Result{}, err
	}

	// 3) Delete objects which should not be there, update existing objects and create missing ones.
	var name string
	for _, ingressNodeFirewallCurrentNodeState := range ingressNodeFirewallNodeStateList.Items {
		// First, check if the desired specs contain a possibly new spec for the current node state object.
		name = ingressNodeFirewallCurrentNodeState.Name
		nodeStateDesiredSpec, ok := nodeStateDesiredSpecs[name]
		// If the current state object is not found in the list of desired states, then we must delete the current node
		// state object.
		if !ok {
			if err := r.Delete(ctx, &ingressNodeFirewallCurrentNodeState); err != nil && !errors.IsNotFound(err) {
				r.Log.Error(err, "Failed to delete node state",
					"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
					"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
				return ctrl.Result{}, err
			}
			r.Log.Info("Deleted object",
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
			continue
		}

		// If the node name was found, but the specs are equal, continue with the next current node state.
		// Also, remove the object from the nodeStateDesiredSpecs so that we can later iterate over the items
		// that must still be created.
		if equality.Semantic.DeepEqual(ingressNodeFirewallCurrentNodeState.Spec, nodeStateDesiredSpec) {
			r.Log.Info("No change detected, skipping",
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
			delete(nodeStateDesiredSpecs, name)
			continue
		}

		// Otherwise, if the specs do not match, update the current node state.
		// Also, remove the object from the nodeStateDesiredSpecs so that we can later iterate over the items
		// that must still be created.
		ingressNodeFirewallCurrentNodeState.Spec = nodeStateDesiredSpec
		err = r.Update(ctx, &ingressNodeFirewallCurrentNodeState)
		if err != nil {
			r.Log.Error(err, "Failed to update IngressNodeFirewallNodeState",
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
			return ctrl.Result{}, err
		}
		r.Log.Info("Updated object",
			"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
			"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
		delete(nodeStateDesiredSpecs, name)
		continue
	}

	// Create all node states which are still inside the remaining desired specs.
	for nodeToCreate, nodeStateDesiredSpec := range nodeStateDesiredSpecs {
		ingressNodeFirewallNodeState := infv1alpha1.IngressNodeFirewallNodeState{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeToCreate,
				Namespace: r.Namespace,
			},
			Spec: nodeStateDesiredSpec,
		}
		err = r.Create(ctx, &ingressNodeFirewallNodeState)
		if err != nil {
			r.Log.Error(err, "Failed to create new IngressNodeFirewallNodeState",
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
			return ctrl.Result{}, err
		}
		r.Log.Info("Created object",
			"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace,
			"ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
	}

	return ctrl.Result{}, nil
}

// triggerReconciliation triggers reconciliation for the first ingressnodefwv1alpha1.IngressNodeFirewall object that it
// can find. Triggering reconciliation for a single object suffices because the IngressNodeFirewall reconciler will list
// and reconcile all dependant resources with each reconciliation.
// TODO: Limit reconciliation requests -> only reconcile if object.GetLabels() matches an IngressNodeFirewall with a
// matching label.
func (r *IngressNodeFirewallReconciler) triggerReconciliation(object client.Object) []reconcile.Request {
	ingressNodeFirewallList := infv1alpha1.IngressNodeFirewallList{}
	listOpts := []client.ListOption{}
	if err := r.List(context.TODO(), &ingressNodeFirewallList, listOpts...); err != nil {
		r.Log.Error(err, "Failed to list IngressNodeFirewall objects")
		return []reconcile.Request{}
	}

	// We do not need to reconcile anything if there are no items of type IngressNodeFirwall.
	if len(ingressNodeFirewallList.Items) == 0 {
		return []reconcile.Request{}
	}

	// Reconcile only for a single item.
	nodeState := ingressNodeFirewallList.Items[0]
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      nodeState.Name,
				Namespace: nodeState.Namespace,
			},
		},
	}
}

// SetupWithManager sets up the controller with the Manager. In addition to watching IngressNodeFirewall
// this also watches objects of Kind Node.
func (r *IngressNodeFirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infv1alpha1.IngressNodeFirewall{}).
		Watches(
			&source.Kind{Type: &v1.Node{}},
			handler.EnqueueRequestsFromMapFunc(r.triggerReconciliation)).
		Complete(r)
}

// buildNodeStateSpecs reads a list of *ingressnodefwv1alpha1.IngressNodeFirewallList and builds an appropriate mapping
// of node => IngressNodeFirewallNodeStateSpec.
// TODO: settle on a logic for the merges.
func (r *IngressNodeFirewallReconciler) buildNodeStateSpecs(
	ctx context.Context, ingressNodeFirewallList *infv1alpha1.IngressNodeFirewallList) (map[string]infv1alpha1.IngressNodeFirewallNodeStateSpec, error) {
	var err error
	nodeList := v1.NodeList{}
	nodeIngressRuleSet := make(map[string][]infv1alpha1.IngressNodeFirewallRules)
	nodeInterfaceSet := map[string]sets.String{}

	// Build the rule sets and interface lists per node.
	// For each IngressNodeFirewall object, retrieve all nodes that match the label selector.
	// Now, for each matching node, combine all rules for this node (TODO: combine unique rules)
	// and all interfaces.
	for _, firewallObj := range ingressNodeFirewallList.Items {
		listOpts := []client.ListOption{
			client.MatchingLabels(firewallObj.Spec.NodeSelector.MatchLabels),
		}
		err = r.List(ctx, &nodeList, listOpts...)
		if err != nil {
			return nil, err
		}

		for _, node := range nodeList.Items {
			if _, ok := nodeIngressRuleSet[node.Name]; !ok {
				nodeIngressRuleSet[node.Name] = []infv1alpha1.IngressNodeFirewallRules{}
			}
			if _, ok := nodeInterfaceSet[node.Name]; !ok {
				nodeInterfaceSet[node.Name] = sets.String{}
			}
			nodeIngressRuleSet[node.Name] = append(nodeIngressRuleSet[node.Name], firewallObj.Spec.Ingress...)
			if firewallObj.Spec.Interfaces != nil {
				nodeInterfaceSet[node.Name].Insert(firewallObj.Spec.Interfaces...)
			}
		}
	}

	nodeStateSpecs := make(map[string]infv1alpha1.IngressNodeFirewallNodeStateSpec, len(nodeIngressRuleSet))
	for node, ingressRule := range nodeIngressRuleSet {
		interfaceList := nodeInterfaceSet[node].List()
		nodeStateSpecs[node] = infv1alpha1.IngressNodeFirewallNodeStateSpec{
			Ingress:    ingressRule,
			Interfaces: interfaceList,
		}
	}

	return nodeStateSpecs, nil
}
