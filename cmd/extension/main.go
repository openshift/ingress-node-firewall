package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	// Import OTP test packages from this module
	_ "github.com/openshift/ingress-node-firewall/test/e2e/functional/tests"
	_ "github.com/openshift/ingress-node-firewall/test/e2e/validation/tests"
)

func main() {
	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "ingress-node-firewall")

	// Register test suites (parallel, serial, disruptive, all)
	registerSuites(ext)

	// Build test specs from Ginkgo
	// Note: ModuleTestsOnly() is applied by default, which filters out /vendor/ and k8s.io/kubernetes tests
	allSpecs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	// Filter to only include tests from this module's test/e2e/ directories
	// Excludes tests from /go/pkg/mod/ (module cache) and /vendor/
	componentSpecs := allSpecs.Select(func(spec *et.ExtensionTestSpec) bool {
		for _, loc := range spec.CodeLocations {
			// Include tests from test/e2e/functional/tests/ and test/e2e/validation/tests/
			if (strings.Contains(loc, "/test/e2e/functional/tests/") || strings.Contains(loc, "/test/e2e/validation/tests/")) &&
			   !strings.Contains(loc, "/go/pkg/mod/") && !strings.Contains(loc, "/vendor/") {
				return true
			}
		}
		return false
	})

	// Process all specs
	componentSpecs.Walk(func(spec *et.ExtensionTestSpec) {
		// Apply platform filters based on Platform: labels
		for label := range spec.Labels {
			if strings.HasPrefix(label, "Platform:") {
				platformName := strings.TrimPrefix(label, "Platform:")
				spec.Include(et.PlatformEquals(platformName))
			}
		}

		// Apply platform filters based on [platform:xxx] in test names
		re := regexp.MustCompile(`\[platform:([a-z]+)\]`)
		if match := re.FindStringSubmatch(spec.Name); match != nil {
			platform := match[1]
			spec.Include(et.PlatformEquals(platform))
		}

		// Set lifecycle to Informing
		spec.Lifecycle = et.LifecycleInforming
	})

	// Add filtered component specs to extension
	ext.AddSpecs(componentSpecs)

	registry.Register(ext)

	root := &cobra.Command{
		Long: "Ingress Node Firewall Tests",
	}

	root.AddCommand(cmd.DefaultExtensionCommands(registry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}

// registerSuites registers test suites with proper categorization
func registerSuites(ext *e.Extension) {
	suites := []e.Suite{
		{
			Name: "ingress-node-firewall/conformance/parallel",
			Parents: []string{
				"openshift/conformance/parallel",
			},
			Description: "Parallel conformance tests (Level0, non-serial, non-disruptive)",
			Qualifiers: []string{
				`name.contains("[Level0]") && !(name.contains("[Serial]") || name.contains("[Disruptive]"))`,
			},
		},
		{
			Name: "ingress-node-firewall/conformance/serial",
			Parents: []string{
				"openshift/conformance/serial",
			},
			Description: "Serial conformance tests (must run sequentially)",
			Qualifiers: []string{
				`name.contains("[Level0]") && name.contains("[Serial]") && !name.contains("[Disruptive]")`,
			},
		},
		{
			Name:        "ingress-node-firewall/disruptive",
			Parents:     []string{"openshift/disruptive"},
			Description: "Disruptive tests (may affect cluster state)",
			Qualifiers: []string{
				`name.contains("[Disruptive]")`,
			},
		},
		{
			Name:        "ingress-node-firewall/non-disruptive",
			Description: "All non-disruptive tests (safe for development clusters)",
			Qualifiers: []string{
				`!name.contains("[Disruptive]")`,
			},
		},
		{
			Name:        "ingress-node-firewall/all",
			Description: "All ingress-node-firewall tests",
			// No qualifiers means all tests from this extension will be included
		},
	}

	for _, suite := range suites {
		ext.AddSuite(suite)
	}
}
