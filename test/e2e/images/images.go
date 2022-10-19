package images

import (
	"fmt"
	"os"
)

var (
	registry string
	netcat   string
)

func init() {
	registry = os.Getenv("IMAGE_REGISTRY")
	if registry == "" {
		registry = "quay.io"
	}

	netcat = os.Getenv("NETCAT_IMAGE")
	if netcat == "" {
		netcat = "openshift/origin-network-tools:latest"
	}
}

func NetcatImage() string {
	return fmt.Sprintf("%s/%s", registry, netcat)
}
