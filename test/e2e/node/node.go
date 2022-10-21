package node

import (
	"context"
	"net"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func IPV4NetworkExists(client *testclient.ClientSet, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	nodesList, err := client.Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		panic("Unable to list nodes")
	}
	if len(nodesList.Items) == 0 {
		panic("No nodes were found")
	}
	node := nodesList.Items[0]

	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(address.Address)
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

func IPV6NetworkExists(client *testclient.ClientSet, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	nodesList, err := client.Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		panic("Unable to list nodes")
	}
	if len(nodesList.Items) == 0 {
		panic("No nodes were found")
	}
	node := nodesList.Items[0]

	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		ip := net.ParseIP(address.Address)
		if ip.To16() != nil {
			return true
		}
	}
	return false
}
