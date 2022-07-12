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

// IngressNodeFirewallICMPRule define ingress node firewall rule for ICMP and ICMPv6 protocols
type IngressNodeFirewallICMPRule struct {
	// ICMPType define ICMP Type Numbers (RFC 792).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Maximum:=255
	// +kubebuilder:validation:Minimum:=0
	// +optional
	ICMPType uint8 `json:"icmpType"`

	// ICMPCode define ICMP Code ID (RFC 792).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Maximum:=16
	// +kubebuilder:validation:Minimum:=0
	// +optional
	ICMPCode uint8 `json:"icmpCode"`
}

// IngressNodeFirewallProtoRule define ingress node firewall rule for TCP, UDP and SCTP protocols
type IngressNodeFirewallProtoRule struct {
	// +kubebuilder:validation:Optional
	// +optional
	Port uint16 `json:"port"`
}

// IngressNodeFirewallProtocolRule define ingress node firewall rule per protocol
type IngressNodeFirewallProtocolRule struct {
	// Order define order of execution of ingress firewall rules .
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum:=1
	// +optional
	Order uint32 `json:"order"`

	// IngressNodeFirewallProtoRule define ingress node firewall rule for TCP, UDP and SCTP protocols.
	// +optional
	ProtocolRule IngressNodeFirewallProtoRule `json:"protoRule"`

	// IngressNodeFirewallICMPRule define ingress node firewall rule for ICMP and ICMPv6 protocols.
	// +optional
	ICMPRule IngressNodeFirewallICMPRule `json:"icmpRule"`

	// Protocol can be ICMP, ICMPv6, TCP, SCTP or UDP.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum="icmp";"icmpv6";"tcp";"udp";"sctp"
	// +optional
	Protocol IngressNodeFirewallRuleProtocolType `json:"protocol"`

	// Action can be allow or deny.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum="allow";"deny"
	// +optional
	Action IngressNodeFirewallActionType `json:"action"`
}

// ProtocolType defines the protocol types that are supported
type IngressNodeFirewallRuleProtocolType string

const (
	// ProtocolTypeICMP refers to the ICMP protocol
	ProtocolTypeICMP IngressNodeFirewallRuleProtocolType = "icmp"

	// ProtocolTypeICMPv6 refers to the ICMPv6 protocol
	ProtocolTypeICMPv6 IngressNodeFirewallRuleProtocolType = "icmpv6"

	// ProtocolTypeTCP refers to the TCP protocol, for either IPv4 or IPv6
	ProtocolTypeTCP IngressNodeFirewallRuleProtocolType = "tcp"

	// ProtocolTypeUDP refers to the UDP protocol, for either IPv4 or IPv6
	ProtocolTypeUDP IngressNodeFirewallRuleProtocolType = "udp"

	// ProtocolTypeSCTP refers to the SCTP protocol, for either IPv4 or IPv6
	ProtocolTypeSCTP IngressNodeFirewallRuleProtocolType = "sctp"
)

// IngressNodeFirewallActionType indicates whether an IngressNodeFirewallRule allows or denies traffic
// +kubebuilder:validation:Pattern=`^allow|deny$`
type IngressNodeFirewallActionType string

const (
	IngressNodeFirewallAllow IngressNodeFirewallActionType = "allow"
	IngressNodeFirewallDeny  IngressNodeFirewallActionType = "deny"
)

// IngressNodeFirewallRules define ingress node firewall rule
type IngressNodeFirewallRules struct {
	// FromCIDRS is A list of CIDR from which we apply node firewall rule
	FromCIDRs []string `json:"fromCIDRs"`
	// FirewallProtocolRules is A list of per protocol ingress node firewall rules
	FirewallProtocolRules []IngressNodeFirewallProtocolRule `json:"rules"`
}

// IngressNodeFirewallSpec defines the desired state of IngressNodeFirewall
type IngressNodeFirewallSpec struct {
	// Selects node(s) where ingress firewall rules will be applied to
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// A list of ingress firewall policy rules.
	// empty list indicates no ingress firewall i.e allow all incoming traffic.
	// +kubebuilder:validation:Optional
	// +optional
	Ingress []IngressNodeFirewallRules `json:"ingress"`
}

// IngressNodeFirewallStatus defines the observed state of IngressNodeFirewall
type IngressNodeFirewallStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// IngressNodeFirewall is the Schema for the ingressnodefirewalls API
type IngressNodeFirewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngressNodeFirewallSpec   `json:"spec,omitempty"`
	Status IngressNodeFirewallStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngressNodeFirewallList contains a list of IngressNodeFirewall
type IngressNodeFirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngressNodeFirewall `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngressNodeFirewall{}, &IngressNodeFirewallList{})
}
