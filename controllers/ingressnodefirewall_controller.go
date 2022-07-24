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
	ingressnodefwv1alpha1 "ingress-node-firewall/api/v1alpha1"
	"time"

	"github.com/go-logr/logr"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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
	log := log.FromContext(ctx)

	// Whenever the reconciler gets triggered (indicating any change to any IngressNodeFirewall object or dependant
	// IngressNodeFirewallNodeState), simply list all objects and write the new IngressNodeFirewallNodeStates.
	// For production, this might certainly be narrowed down a bit.
	// I just coded this reconciler quickly, so this definitely isn't final logic.
	// TODO: missing reconciliation when node labels are updated (!)

	// 1)
	// Get the namespace that the NodeState objects reside in.
	ingressNodeFirewallConfigList := ingressnodefwv1alpha1.IngressNodeFirewallConfigList{}
	if err := r.List(ctx, &ingressNodeFirewallConfigList); err != nil {
		log.Error(err, "Failed to list ingress node firewall configuration")
		return ctrl.Result{}, err
	}
	if len(ingressNodeFirewallConfigList.Items) != 1 || ingressNodeFirewallConfigList.Items[0].Spec.Namespace == "" {
		err := fmt.Errorf("Invalid ingress node firewall config")
		log.Error(err, "Expected only a single ingress node firewall configuration item")
		return ctrl.Result{}, err
	}
	namespace := ingressNodeFirewallConfigList.Items[0].Spec.Namespace

	// 2)
	// Get all IngressNodeFirewall objects (cluster scoped) and build the nodeStateSpecs.
	ingressNodeFirewallList := &ingressnodefwv1alpha1.IngressNodeFirewallList{}
	if err := r.List(ctx, ingressNodeFirewallList); err != nil {
		log.Error(err, "Failed to list ingress node firewalls")
		return ctrl.Result{}, err
	}
	nodeStateSpecs, err := r.buildNodeStateSpecs(ctx, ingressNodeFirewallList)
	if err != nil {
		log.Error(err, "Failed build rules for NodeStates")
		return ctrl.Result{}, err
	}

	// 3)
	// Get all IngressNodeFirewallNodeState in namespace <namespace> (namespace scoped).
	ingressNodeFirewallNodeStateList := ingressnodefwv1alpha1.IngressNodeFirewallNodeStateList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
	}
	if err := r.List(ctx, &ingressNodeFirewallNodeStateList, listOpts...); err != nil {
		log.Error(err, "Failed to list ingress node firewalls")
		return ctrl.Result{}, err
	}

	// 4)
	// Delete objects which should not be there, create objects which are missing and update
	// those which are there and need an update.
	// TODO: iterate over this in a smarter way.
	// First, update or create:
	for node, nodeStateSpec := range nodeStateSpecs {
		for _, ingressNodeFirewallNodeState := range ingressNodeFirewallNodeStateList.Items {
			// Update.
			if ingressNodeFirewallNodeState.Name == node {
				ingressNodeFirewallNodeState.Spec = *nodeStateSpec
				err = r.Update(ctx, &ingressNodeFirewallNodeState)
				if err != nil {
					log.Error(err, "Failed to update IngressNodeFirewallNodeState", "ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace, "ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
					return ctrl.Result{}, err
				}
				// Ask to requeue after 1 minute in order to give enough time for the
				// pods be created on the cluster side and the operand be able
				// to do the next update step accurately.
				return ctrl.Result{RequeueAfter: time.Minute}, nil
			}
			log.Info("Updated object", "IngressNodeFirewallNodeState", ingressNodeFirewallNodeState.Name)
			continue
		}
		// Create.
		ingressNodeFirewallNodeState := ingressnodefwv1alpha1.IngressNodeFirewallNodeState{}
		ingressNodeFirewallNodeState.Name = node
		ingressNodeFirewallNodeState.Namespace = namespace
		ingressNodeFirewallNodeState.Spec = *nodeStateSpec
		err = r.Create(ctx, &ingressNodeFirewallNodeState)
		if err != nil {
			log.Error(err, "Failed to create new IngressNodeFirewallNodeState", "ingressNodeFirewallNodeState.Namespace", ingressNodeFirewallNodeState.Namespace, "ingressNodeFirewallNodeState.Name", ingressNodeFirewallNodeState.Name)
			return ctrl.Result{}, err
		}
		log.Info("Created object", "IngressNodeFirewallNodeState", ingressNodeFirewallNodeState.Name)
		// Deployment created successfully - return and requeue
		return ctrl.Result{Requeue: true}, nil
	}
	// Then, delete:
	for _, ingressNodeFirewallNodeState := range ingressNodeFirewallNodeStateList.Items {
		if _, ok := nodeStateSpecs[ingressNodeFirewallNodeState.Name]; !ok {
			if err := r.Delete(ctx, &ingressNodeFirewallNodeState); err != nil && !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete node state", "nodeState.Name", ingressNodeFirewallNodeState.Name)
				return ctrl.Result{}, err
			}
			log.Info("Deleted object", "IngressNodeFirewallNodeState", ingressNodeFirewallNodeState.Name)
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewall{}).
		Owns(&ingressnodefwv1alpha1.IngressNodeFirewallNodeState{}).
		Complete(r)
}

// buildNodeStateSpecs reads a list of *ingressnodefwv1alpha1.IngressNodeFirewallList and builds an appropriate mapping of
// node => IngressNodeFirewallNodeStateSpec.
// TODO: currently this is just for demo purposes and instead of merging rules from different objects, it just overwrites them.
// TODO: The controller should do the caching for us, so hopefully listing nodes several times shouldn't matter.
func (r *IngressNodeFirewallReconciler) buildNodeStateSpecs(ctx context.Context, ingressNodeFirewallList *ingressnodefwv1alpha1.IngressNodeFirewallList) (map[string]*ingressnodefwv1alpha1.IngressNodeFirewallNodeStateSpec, error) {
	var err error
	nodeStateSpecs := make(map[string]*ingressnodefwv1alpha1.IngressNodeFirewallNodeStateSpec)
	nodeList := v1.NodeList{}
	for _, firewallObj := range ingressNodeFirewallList.Items {
		listOpts := []client.ListOption{
			client.MatchingLabels(firewallObj.Spec.NodeSelector),
		}
		err = r.List(ctx, &nodeList, listOpts...)
		if err != nil {
			return nil, err
		}
		// TODO: implement a merge logic here instead of this obviously wrong
		// overwrite. But good enough for demo purposes.
		for _, node := range nodeList.Items {
			spec := ingressnodefwv1alpha1.IngressNodeFirewallNodeStateSpec{
				Ingress:    firewallObj.Spec.Ingress,
				Interfaces: firewallObj.Spec.Interfaces,
			}
			nodeStateSpecs[node.Name] = &spec
		}
	}

	return nodeStateSpecs, nil
}
