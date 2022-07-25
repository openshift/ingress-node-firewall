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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IngrNodeFwConfigSpec defines the desired state of IngrNodeFwConfig
type IngrNodeFwConfigSpec struct {
	// Nodes where the daemonset will be running on.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// tolerations is a list of tolerations applied to ingress node firewall controller
	// deployments.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// IngrNodeFwConfigStatus defines the observed state of IngrNodeFwConfig
type IngrNodeFwConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// IngrNodeFwConfig is the Schema for the ingrnodefwconfigs API
type IngrNodeFwConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IngrNodeFwConfigSpec   `json:"spec,omitempty"`
	Status IngrNodeFwConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IngrNodeFwConfigList contains a list of IngrNodeFwConfig
type IngrNodeFwConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IngrNodeFwConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IngrNodeFwConfig{}, &IngrNodeFwConfigList{})
}
