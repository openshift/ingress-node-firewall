package status

import (
	"context"
	"time"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"

	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// IngressNodeFirewallConfigResourcesNotReadyError contains Error message
// explaining the reason why ingress node firewall Config is not ready.
type IngressNodeFirewallConfigResourcesNotReadyError struct {
	Message string
}

func (e IngressNodeFirewallConfigResourcesNotReadyError) Error() string { return e.Message }

func (e IngressNodeFirewallConfigResourcesNotReadyError) Is(target error) bool {
	_, ok := target.(*IngressNodeFirewallConfigResourcesNotReadyError)
	return ok
}

const (
	// ConditionAvailable means daemonSet is available and the number of scheduled pods
	// is the same of the number of desired pods.
	ConditionAvailable = "Available"
	// ConditionProgressing means daemonSet is progressing. Progress for a daemonSet
	// is considered when desired pods are being created.
	ConditionProgressing = "Progressing"
	// ConditionDegraded means daemonset availability conditions have not been achieved, when
	// one of its pods fails to be created or deleted.
	ConditionDegraded = "Degraded"
)

// Update updates ingress node firewall config object status field.
func Update(ctx context.Context, client k8sclient.Client, infcfg *ingressnodefwv1alpha1.IngressNodeFirewallConfig, condition string, reason string, message string) error {
	conditions := getConditions(condition, reason, message)
	cfg := infcfg.DeepCopy()
	if !equality.Semantic.DeepEqual(conditions, cfg.Status.Conditions) {
		cfg.Status.Conditions = conditions
		if err := client.Status().Update(ctx, cfg); err != nil {
			return errors.Wrapf(err, "could not update status for object %+v", cfg)
		}
	}
	return nil
}

// getConditions based on the passed in condition it will update the status template
// Status field.
func getConditions(condition string, reason string, message string) []metav1.Condition {
	conditions := getBaseConditions()
	switch condition {
	case ConditionAvailable:
		conditions[0].Status = metav1.ConditionTrue
	case ConditionProgressing:
		conditions[1].Status = metav1.ConditionTrue
		conditions[1].Reason = reason
		conditions[1].Message = message
	case ConditionDegraded:
		conditions[2].Status = metav1.ConditionTrue
		conditions[2].Reason = reason
		conditions[2].Message = message
	}
	return conditions
}

// getBaseConditions return a template list for conditions.
func getBaseConditions() []metav1.Condition {
	now := time.Now()
	return []metav1.Condition{
		{
			Type:               ConditionAvailable,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Time{Time: now},
			Reason:             ConditionAvailable,
		},
		{
			Type:               ConditionProgressing,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Time{Time: now},
			Reason:             ConditionProgressing,
		},
		{
			Type:               ConditionDegraded,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Time{Time: now},
			Reason:             ConditionDegraded,
		},
	}
}

// IsIngressNodeFirewallConfigAvailable check if the availability conditions for ingress node
// firewall config resource have been achieved.
func IsIngressNodeFirewallConfigAvailable(ctx context.Context, client k8sclient.Client, namespace string) error {
	ds := &appsv1.DaemonSet{}
	err := client.Get(ctx, types.NamespacedName{Name: "ingress-node-firewall-daemon", Namespace: namespace}, ds)
	if err != nil {
		return err
	}
	if ds.Status.DesiredNumberScheduled != ds.Status.CurrentNumberScheduled {
		return IngressNodeFirewallConfigResourcesNotReadyError{Message: "IngressNodeFirewall daemon not ready"}
	}
	return nil
}
