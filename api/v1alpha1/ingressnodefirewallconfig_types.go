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

// IngressNodeFirewallConfigSpec defines the desired state of IngressNodeFirewallConfig.
type IngressNodeFirewallConfigSpec struct {
	// nodeSelector is used to select which Nodes the ingress node firewall DaemonSet will be run on.
	// + This field is using map[string]string instead of metav1.LabelSelector because it matches the daemonset NodeSelector template. Thus one cannot benefit from additional match criteria that metav1.LabelSelector provides.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Debug enable debug mode for ingress node firewall ebpf XDP lookup
	//+kubebuilder:default:=false
	// +optional
	Debug *bool `json:"debug,omitempty"`

	// eBPF program manager mode, can either be false for the default mode, or true for the eBPF program manager mode `bpfman`.
	// +kubebuilder:default:=false
	// +optional
	EBPFProgramManagerMode *bool `json:"ebpfProgramManagerMode,omitempty"`
}

// IngressNodeFirewallConfigStatus defines the observed state of IngressNodeFirewallConfig.
type IngressNodeFirewallConfigStatus struct {
	// Conditions show the current state of the Ingress Node Firewall Config resource
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IngressNodeFirewallConfig is the Schema for the ingressnodefirewallconfigs API.
type IngressNodeFirewallConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressNodeFirewallConfigSpec   `json:"spec,omitempty"`
	Status IngressNodeFirewallConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngressNodeFirewallConfigList contains a list of IngressNodeFirewallConfig.
type IngressNodeFirewallConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressNodeFirewallConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngressNodeFirewallConfig{}, &IngressNodeFirewallConfigList{})
}
