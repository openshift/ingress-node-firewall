package e2e

import (
	"os"
)

// GetKubeconfig returns the kubeconfig path from KUBECONFIG env var or default location
func GetKubeconfig() string {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}
	return os.Getenv("HOME") + "/.kube/config"
}
