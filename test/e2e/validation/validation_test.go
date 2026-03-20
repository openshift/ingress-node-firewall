//go:build validationtests
// +build validationtests

package validation

import (
	"flag"
	"os"
	"path"
	"testing"

	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	"github.com/openshift/ingress-node-firewall/test/e2e/k8sreporter"
	_ "github.com/openshift/ingress-node-firewall/test/e2e/validation/tests"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/reporters"
	"github.com/onsi/ginkgo/v2/types"
	. "github.com/onsi/gomega"
)

var OperatorNameSpace = consts.DefaultOperatorNameSpace

var junitPath *string
var reportPath *string

func init() {
	if ns := os.Getenv("OO_INSTALL_NAMESPACE"); len(ns) != 0 {
		OperatorNameSpace = ns
	}

	junitPath = flag.String("junit", "", "the path for the junit format report")
	reportPath = flag.String("report", "", "the path of the report file containing details for failed tests")
}

func TestValidation(t *testing.T) {
	RegisterFailHandler(Fail)

	if *junitPath != "" {
		junitFile := path.Join(*junitPath, "validation_junit.xml")
		ReportAfterSuite("generate JUnit report", func(report types.Report) {
			reporters.GenerateJUnitReport(report, junitFile)
		})
	}

	if *reportPath != "" {
		// TODO: k8sreporter needs migration to Ginkgo v2 API
		// For now, k8sreporter is disabled
		clients := testclient.New("")
		_ = clients
		_ = k8sreporter.New
	}

	RunSpecs(t, "Ingress Node Firewall Operator Validation Suite")
}
