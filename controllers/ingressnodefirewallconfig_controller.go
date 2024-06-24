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
	"os"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/apply"
	"github.com/openshift/ingress-node-firewall/pkg/platform"
	"github.com/openshift/ingress-node-firewall/pkg/render"
	"github.com/openshift/ingress-node-firewall/pkg/status"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultIngressNodeFirewallCrName = "ingressnodefirewallconfig"
	IngressNodeFirewallManifestPath  = "./bindata/manifests/daemon"
	mapsVolumeName                   = "bpf-maps"
	bpfmanMapsVolumeName             = "bpfman-maps"
	bpfFsPath                        = "/sys/fs/bpf"
	bpfManBpfFSPath                  = "/run/ignfw/maps"
	daemonContainerName              = "daemon"
)

var ManifestPath = IngressNodeFirewallManifestPath

// IngressNodeFirewallConfigReconciler reconciles a IngressNodeFirewallConfig object
type IngressNodeFirewallConfigReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Log          logr.Logger
	Namespace    string
	PlatformInfo platform.PlatformInfo
}

// +kubebuilder:rbac:groups=apps,namespace=ingress-node-firewall-system,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewallconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the IngressNodeFirewallConfig object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *IngressNodeFirewallConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	errorMsg, wrappedErrMsg, condition := "", "", ""
	var ctrResult = ctrl.Result{}
	logger := r.Log.WithValues("ingress node firewall config", req.NamespacedName)
	req.Namespace = r.Namespace
	instance := &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	if req.Name != defaultIngressNodeFirewallCrName {
		logger.Error(err, "Invalid IngressNode firewall config resource name", "name", req.Name)
		return ctrl.Result{}, nil // Return success to avoid requeue
	}

	if err = r.syncIngressNodeFwConfigResources(ctx, instance); err != nil {
		condition = status.ConditionDegraded
		err = errors.Wrapf(err, "FailedToSyncIngressNodeFirewallConfigResources")
	} else {
		err = status.IsIngressNodeFirewallConfigAvailable(ctx, r.Client, req.NamespacedName.Namespace)
		if err != nil {
			if _, ok := err.(status.IngressNodeFirewallConfigResourcesNotReadyError); ok {
				ctrResult = ctrl.Result{RequeueAfter: 5 * time.Second}
			}
			condition = status.ConditionProgressing
		} else {
			condition = status.ConditionAvailable
		}
	}

	if err != nil {
		errorMsg = err.Error()
		if errors.Unwrap(err) != nil {
			wrappedErrMsg = errors.Unwrap(err).Error()
		}
	}
	if err = status.Update(context.TODO(), r.Client, instance, condition, errorMsg, wrappedErrMsg); err != nil {
		logger.Info("failed to update ingress node firewall config status", "Desired status", status.ConditionAvailable)
		err = nil
	}
	return ctrResult, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *IngressNodeFirewallConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewallConfig{}).
		Owns(&appsv1.DaemonSet{}).
		Complete(r)
}

func (r *IngressNodeFirewallConfigReconciler) syncIngressNodeFwConfigResources(ctx context.Context, config *ingressnodefwv1alpha1.IngressNodeFirewallConfig) error {
	logger := r.Log.WithName("syncIngressNodeFirewallConfigResources")
	logger.Info("Start")
	data := render.MakeRenderData()

	var useBPFMan bool

	data.Data["Image"] = os.Getenv("DAEMONSET_IMAGE")
	data.Data["NameSpace"] = r.Namespace
	data.Data["RBACProxyImage"] = os.Getenv("KUBE_RBAC_PROXY_IMAGE")
	data.Data["IsOpenShift"] = r.PlatformInfo.IsOpenShift()
	if config.Spec.Debug != nil {
		data.Data["Debug"] = "0"
		if *config.Spec.Debug {
			data.Data["Debug"] = "1"
		}
	}

	if config.Spec.EBPFProgramManagerMode != nil {
		data.Data["EBPFProgramManagerMode"] = "0"
		if *config.Spec.EBPFProgramManagerMode {
			data.Data["EBPFProgramManagerMode"] = "1"
			useBPFMan = true
		}
	}

	objs, err := render.RenderDir(ManifestPath, &data)
	if err != nil {
		logger.Error(err, "Fail to render config daemon manifests")
		return err
	}

	for _, obj := range objs {
		if obj.GetKind() == "DaemonSet" {
			scheme := kscheme.Scheme
			ds := &appsv1.DaemonSet{}
			err = scheme.Convert(obj, ds, nil)
			if err != nil {
				logger.Error(err, "Fail to convert IngressNodeFirewallConfig object to DaemonSet")
				return err
			}
			if len(config.Spec.NodeSelector) > 0 {
				ds.Spec.Template.Spec.NodeSelector = config.Spec.NodeSelector
			}
			daemonContainer := -1
			for idx, c := range ds.Spec.Template.Spec.Containers {
				if c.Name == daemonContainerName {
					daemonContainer = idx
					break
				}
			}

			if daemonContainer != -1 {
				ds.Spec.Template.Spec.Containers[daemonContainer].SecurityContext = &corev1.SecurityContext{
					Privileged: ptr.To[bool](true),
					RunAsUser:  ptr.To[int64](0),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"CAP_BPF",
							"CAP_NET_ADMIN",
						},
					},
				}

				if useBPFMan {
					ds.Spec.Template.Spec.Containers[daemonContainer].VolumeMounts = append(
						ds.Spec.Template.Spec.Containers[daemonContainer].VolumeMounts,
						corev1.VolumeMount{
							Name:             bpfmanMapsVolumeName,
							MountPath:        bpfManBpfFSPath,
							MountPropagation: newMountPropagationMode(corev1.MountPropagationBidirectional),
						})
					ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes,
						corev1.Volume{
							Name: bpfmanMapsVolumeName,
							VolumeSource: corev1.VolumeSource{
								CSI: &corev1.CSIVolumeSource{
									Driver: "csi.bpfman.io",
									VolumeAttributes: map[string]string{
										"csi.bpfman.io/program": "ingress-node-firewall",
										"csi.bpfman.io/maps":    "ingress_node_firewall_events_map,ingress_node_firewall_statistics_map,ingress_node_firewall_table_map,ingress_node_firewall_dbg_map",
									},
								},
							},
						})
				} else {
					ds.Spec.Template.Spec.Containers[daemonContainer].VolumeMounts = append(
						ds.Spec.Template.Spec.Containers[daemonContainer].VolumeMounts,
						corev1.VolumeMount{
							Name:             mapsVolumeName,
							MountPath:        bpfFsPath,
							MountPropagation: newMountPropagationMode(corev1.MountPropagationBidirectional),
						})
					ds.Spec.Template.Spec.Volumes = append(ds.Spec.Template.Spec.Volumes,
						corev1.Volume{
							Name: mapsVolumeName,
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: bpfFsPath,
									Type: newHostPathType(corev1.HostPathDirectoryOrCreate),
								},
							},
						})
				}
			}

			if err := ctrl.SetControllerReference(config, ds, r.Scheme); err != nil {
				return errors.Wrapf(err, "Failed to set controller reference to %s %s", obj.GetNamespace(), obj.GetName())
			}
			err = scheme.Convert(ds, obj, nil)
			if err != nil {
				logger.Error(err, "Fail to convert DaemonSet to IngressNodeFirewallConfig object")
				return err
			}

			if err := apply.ApplyObject(ctx, r.Client, obj); err != nil {
				return errors.Wrapf(err, "could not apply (%s) %s", obj.GroupVersionKind(), obj.GetName())
			}
		}
	}
	return nil
}

// newHostPathType returns a pointer to a given corev1.HostPathType.
// This utility function simplifies the creation of pointer references
// to HostPathType constants, essential for Kubernetes API fields that
// require pointers.
func newHostPathType(pathType corev1.HostPathType) *corev1.HostPathType {
	hostPathType := new(corev1.HostPathType)
	*hostPathType = pathType
	return hostPathType
}

// newMountPropagationMode returns a pointer to a given
// corev1.MountPropagationMode. This utility function simplifies the
// creation of pointer references to MountPropagationMode constants,
// essential for Kubernetes API fields that require pointers.
func newMountPropagationMode(m corev1.MountPropagationMode) *corev1.MountPropagationMode {
	mode := new(corev1.MountPropagationMode)
	*mode = m
	return mode
}
