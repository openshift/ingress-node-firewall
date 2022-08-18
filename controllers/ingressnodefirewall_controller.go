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
	"fmt"

	"github.com/go-logr/logr"

	infv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	// 1) Get all IngressNodeFirewallNodeState objects in namespace <namespace> (namespace scoped).
	r.Log.Info("Getting all IngressNodeFirewallNodeState objects in namespace",
		"req.Name", req.Name, "r.Namespace", r.Namespace)
	ingressNodeFirewallNodeStateList := infv1alpha1.IngressNodeFirewallNodeStateList{}
	listOpts := []client.ListOption{
		client.InNamespace(r.Namespace),
	}
	if err := r.List(ctx, &ingressNodeFirewallNodeStateList, listOpts...); err != nil {
		r.Log.Error(err, "Failed to list ingress node firewalls")
		return ctrl.Result{}, err
	}

	// 2) Get all IngressNodeFirewall objects (cluster scoped) and build the nodeStateSpecs.
	//    nodeStateSpec is a map[<nodeName>]<IngressNodeFirewallNodeStateSpec>.
	r.Log.Info("Getting all IngressNodeFirewall objects", "req.Name", req.Name)
	ingressNodeFirewallList := &infv1alpha1.IngressNodeFirewallList{}
	if err := r.List(ctx, ingressNodeFirewallList); err != nil {
		r.Log.Error(err, "Failed to list IngressNodeFirewall objects")
		return ctrl.Result{}, err
	}
	r.Log.Info("Building the desired node state specs", "req.Name", req.Name)
	desiredNodeStates, err := r.buildNodeStates(ctx, ingressNodeFirewallList)
	if err != nil {
		r.Log.Error(err, "Failed to build IngressNodeFirewallNodeState")
		return ctrl.Result{}, err
	}

	// 3) Delete objects which should not be there, update existing objects and create missing ones.
	var name string
	for _, ingressNodeFirewallCurrentNodeState := range ingressNodeFirewallNodeStateList.Items {
		// First, check if the desired specs contain a possibly new spec for the current node state object.
		name = ingressNodeFirewallCurrentNodeState.Name
		desiredNodeState, ok := desiredNodeStates[name]
		// If the current state object is not found in the list of desired states, then we must delete the current node
		// state object.
		if !ok {
			r.Log.Info("Existing object not found in desired list, triggering deletion", "req.Name", req.Name)
			if err := r.Delete(ctx, &ingressNodeFirewallCurrentNodeState); err != nil && !errors.IsNotFound(err) {
				r.Log.Error(err, "Failed to delete node state",
					"req.Name", req.Name,
					"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
					"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
				return ctrl.Result{}, err
			}
			continue
		}

		// If the node name was found ...
		// a) compare the specs or owner reference. If the specs or owner reference are different, update the current spec.
		if !equality.Semantic.DeepEqual(ingressNodeFirewallCurrentNodeState.Spec, desiredNodeState.Spec) ||
			!equality.Semantic.DeepEqual(ingressNodeFirewallCurrentNodeState.OwnerReferences, desiredNodeState.OwnerReferences) {
			// Otherwise, if the Spec and/or Status does not match, update the current node state.
			// Also, remove the object from the nodeStateDesiredSpecs so that we can later iterate over the items
			// that must still be created.
			r.Log.Info("Existing object found but it has a different Spec or OwnerReferences, triggering update",
				"req.Name", req.Name,
				"ingressNodeFirewallCurrentNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
			// i) Update the Spec.
			ingressNodeFirewallCurrentNodeState.Spec = desiredNodeState.Spec
			ingressNodeFirewallCurrentNodeState.OwnerReferences = desiredNodeState.OwnerReferences
			err = r.Update(ctx, &ingressNodeFirewallCurrentNodeState)
			if err != nil {
				r.Log.Error(err, "Failed to update IngressNodeFirewallNodeState",
					"req.Name", req.Name,
					"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
					"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
				return ctrl.Result{}, err
			}
			// Report success via a log message.
			r.Log.Info("Updated object Spec",
				"req.Name", req.Name,
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
		}
		// b) compare the status. If the status is different, update it.
		if !equality.Semantic.DeepEqual(ingressNodeFirewallCurrentNodeState.Status, desiredNodeState.Status) {
			// ii) Update the resource's status field. Unfortunately, we cannot do this at the same time as the
			// Spec update, so this has to go into a second step.
			r.Log.Info("Existing object found but it has a different Status, triggering Status update",
				"req.Name", req.Name,
				"ingressNodeFirewallCurrentNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
			ingressNodeFirewallCurrentNodeState.Status = desiredNodeState.Status
			err = r.Status().Update(ctx, &ingressNodeFirewallCurrentNodeState)
			if err != nil {
				r.Log.Error(err, "Failed to update IngressNodeFirewallNodeState status",
					"req.Name", req.Name,
					"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
					"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
				return ctrl.Result{}, err
			}
			// Report success via a log message.
			r.Log.Info("Updated object Status",
				"req.Name", req.Name,
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallCurrentNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallCurrentNodeState.Name)
		}
		// Also, remove the object from the nodeStateDesiredSpecs so that we can later iterate over the items
		// that must still be created.
		delete(desiredNodeStates, name)
	}

	// Create all node states which are still inside the remaining desired specs.
	for nodeToCreate, desiredNodeState := range desiredNodeStates {
		r.Log.Info("Object node found, triggering creation", "req.Name", req.Name, "nodeToCreate", nodeToCreate)
		// a) Create the new resource - this will set the spec.
		ingressNodeFirewallNodeState := infv1alpha1.IngressNodeFirewallNodeState{
			ObjectMeta: metav1.ObjectMeta{
				Name:            nodeToCreate,
				Namespace:       r.Namespace,
				OwnerReferences: desiredNodeState.OwnerReferences,
			},
			Spec: desiredNodeState.Spec,
		}
		err = r.Create(ctx, &ingressNodeFirewallNodeState)
		if err != nil {
			r.Log.Error(err, "Failed to create new IngressNodeFirewallNodeState",
				"req.Name", req.Name,
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
			return ctrl.Result{}, err
		}
		// b) Update the resource's status field. Unfortunately, we cannot do this at the same time as the
		// actual creation, so this has to go into a second step.
		ingressNodeFirewallNodeState.Status = desiredNodeState.Status
		err = r.Status().Update(ctx, &ingressNodeFirewallNodeState)
		if err != nil {
			r.Log.Error(err, "Failed to update IngressNodeFirewallNodeState status after creation",
				"req.Name", req.Name,
				"ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace,
				"ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
			return ctrl.Result{}, err
		}
		// Report success via a log message.
		r.Log.Info("Created object",
			"req.Name", req.Name,
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

	// We do not need to reconcile anything if there are no items of type IngressNodeFirewall.
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

// SetupWithManager sets up the controller with the Manager.
// In addition to watching IngressNodeFirewall this also watches all objects of Kind Node and any change to a node
// will trigger a reconciliation request.
// Additionally, changes to objects of type IngressNodeFirewallNodeState with an owner references will lead to
// reconciliation as well. Given that an IngressNodeFirewallNodeState can have multiple owners, reconciliation will
// be triggered for any of them (thus, IsController: false).
func (r *IngressNodeFirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infv1alpha1.IngressNodeFirewall{}).
		Watches(
			&source.Kind{Type: &v1.Node{}},
			handler.EnqueueRequestsFromMapFunc(r.triggerReconciliation)).
		Watches(
			&source.Kind{Type: &infv1alpha1.IngressNodeFirewallNodeState{}},
			&handler.EnqueueRequestForOwner{OwnerType: &infv1alpha1.IngressNodeFirewall{}, IsController: false}).
		Complete(r)
}

// buildNodeStates reads a list of *ingressnodefwv1alpha1.IngressNodeFirewallList and builds an appropriate mapping
// of <nodeName> to IngressNodeFirewallNodeState.
func (r *IngressNodeFirewallReconciler) buildNodeStates(
	ctx context.Context, infList *infv1alpha1.IngressNodeFirewallList) (map[string]infv1alpha1.IngressNodeFirewallNodeState, error) {
	var err error
	nodeList := v1.NodeList{}
	nodeStates := make(map[string]infv1alpha1.IngressNodeFirewallNodeState)

	// Build the NodeStates in a map [<nodeName>]IngressNodeFirewallNodeState.
	// Iterate over all IngressNodeFirewall objects. Get all nodes that are matched by an IngressNodeFirewall object.
	// IngressNodeFirewall objects apply their Ingress rules to a slice of Interfaces. We translate this for
	// IngressNodeFirewallNodeState to a map [<interface name>][]IngressNodeFirewallNodeState.
	// A tuple of {Nodes,Interface name} may be matched by multiple IngressNodeFirewall objects, so merge
	// InterfaceIngressRules[<interface name>] if necessary.
	// If any issue with processing is found along the way, set the node's SyncStatus to SyncError and skip the node
	// in any further iteration.
	for _, firewallObj := range infList.Items {
		firewallObj := firewallObj
		listOpts := []client.ListOption{
			client.MatchingLabels(firewallObj.Spec.NodeSelector.MatchLabels),
		}
		err = r.List(ctx, &nodeList, listOpts...)
		if err != nil {
			return nil, err
		}

	withNextNode:
		for _, node := range nodeList.Items {
			// Create the node state object if it does not exist yet. Otherwise, use the existing state.
			// We use this additional variable because struct fields in a map cannot be manipulated directly in golang.
			// At the end of this loop, we will write back the state to the map with nodeStates[node.Name] = state.
			var state infv1alpha1.IngressNodeFirewallNodeState
			if _, ok := nodeStates[node.Name]; ok {
				state = nodeStates[node.Name]
			} else {
				state = infv1alpha1.IngressNodeFirewallNodeState{}
				state.Spec.InterfaceIngressRules = make(map[string][]infv1alpha1.IngressNodeFirewallRules)
			}

			// Build and/or update the node state object's owner reference.
			ownerRefFound := false
			for _, ownerReference := range state.OwnerReferences {
				if ownerReference.Kind == firewallObj.Kind &&
					ownerReference.APIVersion == firewallObj.APIVersion &&
					ownerReference.Name == firewallObj.Name &&
					ownerReference.UID == firewallObj.UID {
					ownerRefFound = true
					break
				}
			}
			if !ownerRefFound {
				state.OwnerReferences = append(state.OwnerReferences, metav1.OwnerReference{
					APIVersion: firewallObj.APIVersion,
					Kind:       firewallObj.Kind,
					Name:       firewallObj.Name,
					UID:        firewallObj.UID,
				})
			}

			// Check the current synchronization status. If the status indicates a synchronization error then
			// continue with the next node.
			if state.Status.SyncStatus == infv1alpha1.SyncError {
				continue withNextNode
			}
			// Otherwise, the current status will be either empty or ok, hence simply
			// set it to SyncOK.
			state.Status.SyncStatus = infv1alpha1.SyncOK

			// Now, iterate over all interfaces in the InrgessNodeFirewallSpec.
			if len(firewallObj.Spec.Interfaces) == 0 {
				state.Status = infv1alpha1.IngressNodeFirewallNodeStateStatus{
					SyncStatus:       infv1alpha1.SyncError,
					SyncErrorMessage: fmt.Sprintf("Invalid interface name - cannot provide an empty list"),
				}
				// Write back the state to the map and then continue with the next node.
				nodeStates[node.Name] = state
				continue withNextNode
			}
			for _, iface := range firewallObj.Spec.Interfaces {
				// Create the rules for the node spec if they do not yet exist for this interface.
				if _, ok := state.Spec.InterfaceIngressRules[iface]; !ok {
					state.Spec.InterfaceIngressRules[iface] = []infv1alpha1.IngressNodeFirewallRules{}
				}
				// Merge in rules.
				state.Spec.InterfaceIngressRules[iface], err = mergeRuleSet(
					state.Spec.InterfaceIngressRules[iface], firewallObj.Spec.Ingress)
				// On error, report the error in the status field and continue with the next node.
				if err != nil {
					state.Status = infv1alpha1.IngressNodeFirewallNodeStateStatus{
						SyncStatus:       infv1alpha1.SyncError,
						SyncErrorMessage: fmt.Sprintf("Illegal ruleset merge operation, err: %q", err),
					}
					// Write back the state to the map and then continue with the next node.
					nodeStates[node.Name] = state
					continue withNextNode
				}
			}
			// Write back the state to the map.
			nodeStates[node.Name] = state
		}

		firewallObj.Status.SyncStatus = infv1alpha1.FirewallRulesSyncOK
		for _, node := range nodeList.Items {
			if nodeStates[node.Name].Status.SyncStatus == infv1alpha1.SyncError {
				firewallObj.Status.SyncStatus = infv1alpha1.FirewallRulesSyncError
				break
			}
		}
		if err := r.Status().Update(ctx, &firewallObj); err != nil {
			return nil, fmt.Errorf("failed to update ingress node firewall obj status %q", err)
		}
	}

	return nodeStates, nil
}

// mergeRuleSet merges 2 rulesets of type []infv1alpha1.IngressNodeFirewallRules.
// Ruleset a and the returned ruleset will go into IngressNodeFirewallNodeState. Therefore, for ruleset a and for
// the returned ruleset, SourceCIDRs must be of length 1.
// Ruleset b comes from IngressNoeFirewall. Therefore, for ruleset b, SourceCIDRs can have any length >= 1.
func mergeRuleSet(a, b []infv1alpha1.IngressNodeFirewallRules) ([]infv1alpha1.IngressNodeFirewallRules, error) {
	var err error

	// Go over each rule that shall be merged in.
	for _, ruleB := range b {
		// In the b slice, we can potentially have multiple sourceCIDRs per rule.
		// In the a slice, we want to avoid this so that we won't run into any ambiguous situations with the
		// uniqueness of Order.
	withNextSourceCIDR:
		for _, sourceCIDR := range ruleB.SourceCIDRs {
			// Now, go over each existing rule in the already merged slice.
			for i, ruleA := range a {
				if len(ruleA.SourceCIDRs) != 1 {
					return nil, fmt.Errorf(
						"cannot merge into ruleset A with invalid SourceCIDRs: '%v'", ruleA.SourceCIDRs)
				}
				// If the CIDR already exists in A, then merge it in and continue with the next CIDR.
				if ruleA.SourceCIDRs[0] == sourceCIDR {
					a[i].FirewallProtocolRules, err = mergeFirewallProtocolRules(
						ruleA.FirewallProtocolRules, ruleB.FirewallProtocolRules)
					if err != nil {
						return nil, err
					}
					continue withNextSourceCIDR
				}
			}
			// If the CIDR was not found, append the rules to A.
			a = append(a, infv1alpha1.IngressNodeFirewallRules{
				SourceCIDRs:           []string{sourceCIDR},
				FirewallProtocolRules: ruleB.FirewallProtocolRules,
			})
		}
	}
	return a, nil
}

// mergeFirewallProtocolRules merges slices b of type []infv1alpha1.IngressNodeFirewallProtocolRule int slice a
// of type []infv1alpha1.IngressNodeFirewallProtocolRule. The function throws an error if duplicate orders are found.
func mergeFirewallProtocolRules(a, b []infv1alpha1.IngressNodeFirewallProtocolRule) ([]infv1alpha1.IngressNodeFirewallProtocolRule, error) {
	orderList := make(map[uint32]struct{})
	for _, itemA := range a {
		if _, ok := orderList[itemA.Order]; ok {
			return nil, fmt.Errorf("duplicate order %d detected for rules in A", itemA.Order)
		}
		orderList[itemA.Order] = struct{}{}
	}
	for _, itemB := range b {
		if _, ok := orderList[itemB.Order]; ok {
			return nil, fmt.Errorf("duplicate order %d detected for rules in B", itemB.Order)
		}
		orderList[itemB.Order] = struct{}{}
		a = append(a, itemB)
	}
	return a, nil
}
