package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// OCClient provides helper methods for executing oc commands
type OCClient struct {
	kubeconfig string
}

// NewOCClient creates a new OCClient
func NewOCClient(kubeconfig string) *OCClient {
	if kubeconfig == "" {
		kubeconfig = GetKubeconfig()
	}
	return &OCClient{
		kubeconfig: kubeconfig,
	}
}

// Run executes an oc command and returns the output
func (c *OCClient) Run(ctx context.Context, args ...string) (string, error) {
	cmdArgs := append([]string{"--kubeconfig", c.kubeconfig}, args...)
	cmd := exec.CommandContext(ctx, "oc", cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command failed: %v, stderr: %s", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// Get gets a resource
func (c *OCClient) Get(ctx context.Context, resourceType, name, namespace string) (string, error) {
	args := []string{"get", resourceType}
	if name != "" {
		args = append(args, name)
	}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	return c.Run(ctx, args...)
}
