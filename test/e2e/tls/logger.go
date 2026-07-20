package tls

import (
	. "github.com/onsi/ginkgo"
)

// LogStep outputs a major test step using Ginkgo's By() for visibility in test reports
func LogStep(description string) {
	By(description)
}
