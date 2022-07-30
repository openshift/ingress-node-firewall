//go:build e2etests
// +build e2etests

package functional

import (
	"flag"
	"os"
	"path"
	"testing"

	"github.com/openshift/ingress-node-firewall/test/consts"
	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	_ "github.com/openshift/ingress-node-firewall/test/e2e/functional/tests"
	"github.com/openshift/ingress-node-firewall/test/e2e/k8sreporter"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
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

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)

	rr := []Reporter{}
	if *junitPath != "" {
		junitFile := path.Join(*junitPath, "e2e_junit.xml")
		rr = append(rr, reporters.NewJUnitReporter(junitFile))
	}

	clients := testclient.New("")

	if *reportPath != "" {
		rr = append(rr, k8sreporter.New(clients, OperatorNameSpace, *reportPath))
	}

	RunSpecsWithDefaultAndCustomReporters(t, "Ingress Node Firewall Operator E2E Suite", rr)
}
