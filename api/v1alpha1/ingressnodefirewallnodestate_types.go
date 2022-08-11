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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IngressNodeFirewallNodeStateSpec defines the desired state of IngressNodeFirewallNodeState.
type IngressNodeFirewallNodeStateSpec struct {
	// interfaceIngressRules is a map that matches interface names to ingress firewall policy rules that shall be
	// applied on the given interface.
	// An empty map indicates no ingress firewall rules shall be applied, i.e allow all incoming traffic.
	// +kubebuilder:validation:Required
	InterfaceIngressRules map[string][]IngressNodeFirewallRules `json:"interfaceIngressRules"`
}

// IngressNodeFirewallNodeStateStatus defines the observed state of IngressNodeFirewallNodeState.
type IngressNodeFirewallNodeStateStatus struct {
	// syncStatus indicates if this IngressNodeFirewallNodeState object could be successfully generated
	// from the input IngressNodeFirewall objects or if any issues occurred during this object's generation.
	SyncStatus IngressNodeFirewallNodeStateSyncStatus `json:"syncStatus,omitempty"`
	// syncErrorMessage contains futher information about the encountered synchronization error.
	SyncErrorMessage string `json:"syncErrorMessage,omitempty"`
}

// IngressNodeFirewallNodeStateSyncStatus defines the various valid synchronization states for
// IngressNodeFirewallNodeState.
type IngressNodeFirewallNodeStateSyncStatus string

var (
	// SyncError indicates that the last synchronization attempt failed.
	SyncError IngressNodeFirewallNodeStateSyncStatus = "Error"
	// SyncError indicates that the last synchronization attempt was a success.
	SyncOK IngressNodeFirewallNodeStateSyncStatus = "Synchronized"
)

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IngressNodeFirewallNodeState is the Schema for the ingressnodefirewallnodestates API.
type IngressNodeFirewallNodeState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressNodeFirewallNodeStateSpec   `json:"spec,omitempty"`
	Status IngressNodeFirewallNodeStateStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngressNodeFirewallNodeStateList contains a list of IngressNodeFirewallNodeState.
type IngressNodeFirewallNodeStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressNodeFirewallNodeState `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngressNodeFirewallNodeState{}, &IngressNodeFirewallNodeStateList{})
}
