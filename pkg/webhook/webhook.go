package webhook

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"

	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	"github.com/openshift/ingress-node-firewall/pkg/constants"
	"github.com/openshift/ingress-node-firewall/pkg/failsaferules"
	"github.com/openshift/ingress-node-firewall/pkg/utils"

	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type IngressNodeFirewallWebhook struct {
	ingressnodefwv1alpha1.IngressNodeFirewall
}

type (
	empty     struct{}
	uint32Set map[uint32]empty
)

// +kubebuilder:webhook:path=/validate-ingressnodefirewall-openshift-io-v1alpha1-ingressnodefirewall,mutating=false,failurePolicy=fail,sideEffects=None,groups=ingressnodefirewall.openshift.io,resources=ingressnodefirewalls,verbs=create;update,versions=v1alpha1,name=vingressnodefirewall.kb.io,admissionReviewVersions=v1
var (
	_          webhook.CustomValidator = &IngressNodeFirewallWebhook{ingressnodefwv1alpha1.IngressNodeFirewall{}}
	kubeClient client.Client
)

func (r *IngressNodeFirewallWebhook) SetupWebhookWithManager(mgr ctrl.Manager) error {
	kubeClient = mgr.GetClient()
	return ctrl.NewWebhookManagedBy(mgr).
		For(&ingressnodefwv1alpha1.IngressNodeFirewall{}).
		WithValidator(&IngressNodeFirewallWebhook{}).
		Complete()
}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *IngressNodeFirewallWebhook) ValidateCreate(ctx context.Context, newObj runtime.Object) (warnings admission.Warnings, err error) {
	newINF, ok := newObj.(*ingressnodefwv1alpha1.IngressNodeFirewall)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected an IngressNodeFirewall but got a %T", newObj))
	}

	return nil, validateIngressNodeFirewall(ctx, newINF, kubeClient)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *IngressNodeFirewallWebhook) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (warnings admission.Warnings, err error) {
	newINF, ok := newObj.(*ingressnodefwv1alpha1.IngressNodeFirewall)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected an IngressNodeFirewall but got a %T", newObj))
	}

	return nil, validateIngressNodeFirewall(ctx, newINF, kubeClient)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *IngressNodeFirewallWebhook) ValidateDelete(_ context.Context, _ runtime.Object) (warnings admission.Warnings, err error) {
	return nil, nil
}

func validateIngressNodeFirewall(ctx context.Context, inf *ingressnodefwv1alpha1.IngressNodeFirewall, kubeClient client.Client) error {
	if allErrs := validateINFRules(ctx, inf.Spec.Ingress, inf.Name, inf.Spec.NodeSelector, kubeClient); len(allErrs) > 0 {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: ingressnodefwv1alpha1.GroupVersion.Group, Kind: ingressnodefwv1alpha1.IngressNodeFirewall{}.Kind},
			inf.Name, allErrs)
	}
	if allErrs := validateINFInterfaces(ctx, inf.Spec.Interfaces, inf.Name, kubeClient); len(allErrs) > 0 {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: ingressnodefwv1alpha1.GroupVersion.Group, Kind: ingressnodefwv1alpha1.IngressNodeFirewall{}.Kind},
			inf.Name, allErrs)
	}
	return nil
}

func validateINFInterfaces(ctx context.Context, infInterfaces []string, infName string, kubeClient client.Client) field.ErrorList {
	var allErrs field.ErrorList

	for index, inf := range infInterfaces {
		if inf == "" {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("Spec").Child("interfaces").Index(index),
					infName, "can not use blank interfae names"))
		}
		if len(inf) > unix.IFNAMSIZ {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("Spec").Child("interfaces").Index(index),
					infName, fmt.Sprintf("interface %q is too long", inf)))
		}
		if inf[0] >= '0' && inf[0] <= '9' {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("Spec").Child("interfaces").Index(index),
					infName, fmt.Sprintf("interface %q can't start with a number", inf)))
		}
		if strings.Contains(inf, constants.PinDirDotPlaceholder) {
			allErrs = append(allErrs,
				field.Invalid(field.NewPath("Spec").Child("interfaces").Index(index),
					infName, fmt.Sprintf("interface %q can't contain '%s'", inf, constants.PinDirDotPlaceholder)))
		}
	}
	return allErrs
}

func validateINFRules(ctx context.Context, infRules []ingressnodefwv1alpha1.IngressNodeFirewallRules, infName string,
	nodeSelector v1.LabelSelector, kubeClient client.Client) field.ErrorList {
	var allErrs field.ErrorList

	infList, newErr := getINFList(ctx, kubeClient)
	if newErr != nil {
		allErrs = append(allErrs, newErr)
		return allErrs
	}

	for infRulesIndex, infRule := range infRules {
		if newErrs := validatesourceCIDRs(allErrs, infRule.SourceCIDRs, infRulesIndex, infName); len(newErrs) > 0 {
			allErrs = append(allErrs, newErrs...)
		}

		if newErrs := validateRules(allErrs, infRule.FirewallProtocolRules, infRulesIndex, infName); len(newErrs) > 0 {
			allErrs = append(allErrs, newErrs...)
		}

		if newErrs := validateAgainstExistingINFs(allErrs, infList, infRule.SourceCIDRs, infRule.FirewallProtocolRules,
			infRulesIndex, infName, nodeSelector); len(newErrs) > 0 {
			allErrs = append(allErrs, newErrs...)
		}
	}
	return allErrs
}

func validatesourceCIDRs(allErrs field.ErrorList, sourceCIDRs []string, infRulesIndex int, infName string) field.ErrorList {
	if len(sourceCIDRs) == 0 {
		allErrs = append(allErrs,
			field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("sourceCIDRs"),
				infName, "must be at least one sourceCIDRs"))
	} else {
		for sourceCIDRSIndex, sourceCIDR := range sourceCIDRs {
			if isValid, reason := validateSourceCIDR(sourceCIDR); !isValid {
				allErrs = append(allErrs, field.Invalid(
					field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("sourceCIDRs").Index(sourceCIDRSIndex),
					infName, fmt.Sprintf("must be a valid IPV4 or IPV6 CIDR: %s", reason)))
			}
		}
	}
	return allErrs
}

func validateRules(allErrs field.ErrorList, rules []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule, infRulesIndex int,
	infName string) field.ErrorList {
	if err := validateRuleLength(rules, infRulesIndex, infName); err != nil {
		allErrs = append(allErrs, err)
	}
	if !orderIsUnique(rules) {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules"),
			infName, "must have unique order"))
	}
	for ruleIndex, rule := range rules {
		if err := validateRule(rule, infRulesIndex, ruleIndex, infName); err != nil {
			allErrs = append(allErrs, err)
		}
	}
	return allErrs
}

func validateRule(rule ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule, infRulesIndex, ruleIndex int, infName string) *field.Error {
	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeICMP || rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeICMP6 {
		if isValid, reason := isValidICMPICMPV6Rule(rule); !isValid {
			return field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules").Index(ruleIndex),
				infName, fmt.Sprintf("must be a valid ICMP(V6) rule: %s", reason))
		}
	}

	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeTCP || rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeUDP || rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeSCTP {
		if isValid, reason := isValidTCPUDPSCTPRule(rule); !isValid {
			return field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules").Index(ruleIndex),
				infName, fmt.Sprintf("must be a valid %s rule: %s", rule.ProtocolConfig.Protocol, reason))
		}
	}

	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeTCP || rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeUDP {
		if isConflict, err := isConflictWithSafeRulesTransport(rule); !isConflict && err != nil {
			return field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules").Index(ruleIndex),
				infName, fmt.Sprintf("must be a valid %s rule: %v", rule.ProtocolConfig.Protocol, err))
		} else if isConflict && err != nil {
			return field.Forbidden(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules").Index(ruleIndex),
				err.Error())
		}
	}
	return nil
}

func isConflictWithSafeRulesTransport(rule ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) (bool, error) {
	var failSafeRules []failsaferules.TransportProtoFailSafeRule
	var err error
	var start, end uint16
	var r *ingressnodefwv1alpha1.IngressNodeFirewallProtoRule

	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeTCP {
		failSafeRules = failsaferules.GetTCP()
		r = rule.ProtocolConfig.TCP
	} else if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeUDP {
		failSafeRules = failsaferules.GetUDP()
		r = rule.ProtocolConfig.UDP
	} else {
		return false, fmt.Errorf("unable to determine conflict rules for unknown protocol: %q", rule.ProtocolConfig.Protocol)
	}

	for _, failSafeRule := range failSafeRules {
		if r == nil {
			return false, fmt.Errorf("expected ports to be defined for transport protocol")
		}
		// Its ok for user to add allow rules for failSafe ports in case
		// we will have 0.0.0.0/0 rule at the end to deny all.
		if rule.Action == ingressnodefwv1alpha1.IngressNodeFirewallAllow {
			continue
		}
		if utils.IsRange(r) {
			start, end, err = utils.GetRange(r)
			if err != nil {
				return false, fmt.Errorf("failed to get rule ports range: %v", err)
			}
			if withinRange(failSafeRule.GetPort(), start, end) {
				return true, fmt.Errorf("port range is in conflict with access to %s", failSafeRule.GetServiceName())
			}
		} else {
			start, err = utils.GetPort(r)
			if err != nil {
				return false, err
			}
			if failSafeRule.GetPort() == start {
				return true, fmt.Errorf("port is in conflict with access to %s", failSafeRule.GetServiceName())
			}
		}
	}
	return false, nil
}

func validateRuleLength(infRules []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule, infRulesIndex int, infName string) *field.Error {
	if len(infRules) > failsaferules.MAX_INGRESS_RULES {
		return field.Invalid(field.NewPath("spec").Child("ingress").Index(infRulesIndex).Key("rules"),
			infName, fmt.Sprintf("must be no more than %d rules", failsaferules.MAX_INGRESS_RULES))
	}
	return nil
}

func validateSourceCIDR(sourceCIDR string) (bool, string) {
	if _, _, err := net.ParseCIDR(sourceCIDR); err != nil {
		return false, fmt.Sprintf("must define valid IPV4 or IPV6 CIDR: %s", err.Error())
	}
	return true, ""
}

func isValidICMPICMPV6Rule(rule ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) (bool, string) {
	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeICMP &&
		(rule.ProtocolConfig.ICMP == nil || rule.ProtocolConfig.ICMPv6 != nil) {
		return false, "no ICMP rules defined. Define icmpType/icmpCode"
	}
	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeICMP6 &&
		(rule.ProtocolConfig.ICMPv6 == nil || rule.ProtocolConfig.ICMP != nil) {
		return false, "no ICMPv6 rules defined. Define icmpType/icmpCode"
	}
	if rule.ProtocolConfig.TCP != nil || rule.ProtocolConfig.UDP != nil || rule.ProtocolConfig.SCTP != nil {
		return false, "ports are erroneously defined"
	}
	return true, ""
}

func isValidTCPUDPSCTPRule(rule ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) (bool, string) {
	var r *ingressnodefwv1alpha1.IngressNodeFirewallProtoRule

	if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeTCP && rule.ProtocolConfig.TCP != nil {
		r = rule.ProtocolConfig.TCP
	} else if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeUDP && rule.ProtocolConfig.UDP != nil {
		r = rule.ProtocolConfig.UDP
	} else if rule.ProtocolConfig.Protocol == ingressnodefwv1alpha1.ProtocolTypeSCTP && rule.ProtocolConfig.SCTP != nil {
		r = rule.ProtocolConfig.SCTP
	} else {
		return false, "no port defined"
	}

	if utils.IsRange(r) {
		// GetRange() validates that range is valid and emits an error if this is not the case
		_, _, err := utils.GetRange(r)
		if err != nil {
			return false, fmt.Sprintf("must be a valid port range: %s", err.Error())
		}
	} else {
		_, err := utils.GetPort(r)
		if err != nil {
			return false, fmt.Sprintf("must be a valid port: %s", err.Error())
		}
	}

	if rule.ProtocolConfig.ICMP != nil || rule.ProtocolConfig.ICMPv6 != nil {
		return false, "ICMP type/code defined for a non-ICMP(V6) rule"
	}
	return true, ""
}

func orderIsUnique(rules []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) bool {
	orderSet := uint32Set{}
	for _, rule := range rules {
		orderSet[rule.Order] = empty{}
	}

	return len(orderSet) == len(rules)
}

func withinRange(i, lowerBound, upperBound uint16) bool {
	return i >= lowerBound && i <= upperBound
}

func getINFList(ctx context.Context, kubeClient client.Client) (*ingressnodefwv1alpha1.IngressNodeFirewallList, *field.Error) {
	infList := &ingressnodefwv1alpha1.IngressNodeFirewallList{}
	if err := kubeClient.List(ctx, infList, &client.ListOptions{}); err != nil {
		return nil, field.InternalError(field.NewPath("spec").Child("ingress"),
			fmt.Errorf("failed to get list of IngressNodeFirewalls from Kubernetes API server and therefore unable"+
				" to validate IngressNodeFirewall against existing IngressNodeFirewall: %v", err))
	}
	return infList, nil
}

func validateAgainstExistingINFs(allErrs field.ErrorList, infList *ingressnodefwv1alpha1.IngressNodeFirewallList, newSourceCIDRs []string,
	newRules []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule, newINFRulesIndex int, newINFName string, newNodeSelector v1.LabelSelector) field.ErrorList {

	for _, existingINF := range infList.Items {
		existingINFName := existingINF.Name
		// Need to validate rules only if they are applied to the same Nodes
		if reflect.DeepEqual(existingINF.Spec.NodeSelector, newNodeSelector) {
			for _, existingRules := range existingINF.Spec.Ingress {
				for _, existingSourceCIDR := range existingRules.SourceCIDRs {
					for _, newSourceCIDR := range newSourceCIDRs {
						if strings.TrimSpace(newSourceCIDR) == strings.TrimSpace(existingSourceCIDR) {
							if existingINFName != newINFName && isOrderOverlapping(existingRules.FirewallProtocolRules, newRules) {
								allErrs = append(allErrs,
									field.Invalid(field.NewPath("spec").Child("ingress").Index(newINFRulesIndex).Key("rules"),
										newINFName, fmt.Sprintf("order is not unique for sourceCIDR %q and conflicts with "+
											"IngressNodeFirewall %q", newSourceCIDR, existingINF.Name)))
							}
						}
					}
				}
			}
		}
	}
	return allErrs
}

func isOrderOverlapping(oldRules, newRules []ingressnodefwv1alpha1.IngressNodeFirewallProtocolRule) bool {
	for _, oldRule := range oldRules {
		for _, newRule := range newRules {
			if oldRule.Order == newRule.Order {
				return true
			}
		}
	}
	return false
}
