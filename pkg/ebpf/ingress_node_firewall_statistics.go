package nodefwloader

import (
	"log"
	"time"
)

const maxRules = 100 // Max number of rules per sourceCIDRs

// ingressNodeFwStats collects Ingress node firewall per rule statistics
func (infc *IngNodeFwController) ingressNodeFwStats() {
	objs := infc.objs
	go func() {
		// Read loop reporting the total amount of times the kernel
		// function was entered, once per second.
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		log.Printf("Waiting for statistics update")
		for range ticker.C {
			var ruleStats []BpfRuleStatisticsSt
			for rule := 0; rule < maxRules; rule++ {
				if err := objs.IngressNodeFirewallStatisticsMap.Lookup(uint32(rule), &ruleStats); err != nil {
					log.Printf("Failed to lookup statistics map err: %v", err)
				}
			}
		}
	}()
}
