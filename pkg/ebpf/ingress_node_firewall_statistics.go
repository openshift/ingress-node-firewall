package nodefwloader

import (
	"log"
	"time"
)

const maxRules = 100

func ingressNodeFwStats(objs bpfObjects) error {
	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	log.Printf("Waiting for statistics update")
	for range ticker.C {
		var ruleStats bpfRuleStatisticsSt
		var totalStats []bpfRuleStatisticsSt
		for rule := 0; rule < maxRules; rule++ {
			if err := objs.IngressNodeFirewallStatisticsMap.Lookup(&rule, &ruleStats); err != nil {
				return err
			}
			totalStats = append(totalStats, ruleStats)
		}
	}
	return nil
}
