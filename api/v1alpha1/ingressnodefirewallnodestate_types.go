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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// IngressNodeFirewallNodeStateSpec defines the desired state of IngressNodeFirewallNodeState
type IngressNodeFirewallNodeStateSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// A list of ingress firewall policy rules.
	// empty list indicates no ingress firewall i.e allow all incoming traffic.
	// +kubebuilder:validation:Optional
	// +optional
	Ingress []IngressNodeFirewallRules `json:"ingress"`

	// A list of interfaces where the ingress firewall policy will be applied on.
	// empty list indicates the firewall policy applied on all interfaces
	// +kubebuilder:validation:Optional
	// +optional
	// +nullable
	Interfaces *[]string `json:"interfaces"`
}

// IngressNodeFirewallNodeStateStatus defines the observed state of IngressNodeFirewallNodeState
type IngressNodeFirewallNodeStateStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IngressNodeFirewallNodeState is the Schema for the ingressnodefirewallnodestates API
type IngressNodeFirewallNodeState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressNodeFirewallNodeStateSpec   `json:"spec,omitempty"`
	Status IngressNodeFirewallNodeStateStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngressNodeFirewallNodeStateList contains a list of IngressNodeFirewallNodeState
type IngressNodeFirewallNodeStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressNodeFirewallNodeState `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngressNodeFirewallNodeState{}, &IngressNodeFirewallNodeStateList{})
}
