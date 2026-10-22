package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	_ "github.com/openshift/ingress-node-firewall/test/ote"
)

func main() {
	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "ingress-node-firewall")

	ext.AddSuite(e.Suite{
		Name:       "openshift/ingress-node-firewall/all",
		Parents:    []string{},
		Qualifiers: []string{`name.contains("[sig-network][JIRA:Networking] ingress-node-firewall")`},
	})

	ext.AddSuite(e.Suite{
		Name:       "openshift/ingress-node-firewall/aws",
		Parents:    []string{},
		Qualifiers: []string{`name.contains("[sig-network][JIRA:Networking] ingress-node-firewall") && !labels.exists(l, l=="Baremetal")`},
	})

	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: couldn't build extension test specs from ginkgo: %v\n", err)
		os.Exit(1)
	}

	specs.Walk(func(spec *et.ExtensionTestSpec) {
		if strings.Contains(spec.Name, "[LEVEL0]") {
			spec.Lifecycle = et.LifecycleBlocking
		} else {
			spec.Lifecycle = et.LifecycleInforming
		}
	})

	ext.AddSpecs(specs)
	registry.Register(ext)

	rootCmd := &cobra.Command{
		Use:   "ingress-node-firewall-tests",
		Short: "OpenShift extended tests for ingress-node-firewall",
	}

	rootCmd.AddCommand(cmd.DefaultExtensionCommands(registry)...)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
