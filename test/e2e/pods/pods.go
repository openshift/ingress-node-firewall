package pods

import (
	"context"
	"net"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func EnsureRunning(client *testclient.ClientSet, pod *corev1.Pod, namespace string, retryInterval,
	timeout time.Duration) (*corev1.Pod, error) {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	created, err := client.Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return pod, err
		}
	}

	err = wait.PollImmediate(retryInterval, timeout, func() (done bool, err error) {
		pod, err = client.Pods(namespace).Get(ctx, created.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if pod.Status.Phase == corev1.PodRunning {
			return true, nil
		}
		return false, nil
	})
	return pod, err
}

func EnsureDeleted(client *testclient.ClientSet, pod *corev1.Pod, timeout time.Duration) error {
	ctxCreatePod, cancelCreatePod := context.WithTimeout(context.Background(), timeout)
	defer cancelCreatePod()

	err := client.Pods(pod.Namespace).Delete(ctxCreatePod, pod.Name, metav1.DeleteOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

func EnsureDeletedWithLabel(client *testclient.ClientSet, ns, label string, timeout time.Duration) error {
	podList, err := client.Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return err
	}
	for _, pod := range podList.Items {
		if err = EnsureDeleted(client, &pod, timeout); err != nil {
			return err
		}
	}
	return nil
}

func GetIPV4(ips []corev1.PodIP) string {
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip.IP)
		if parsedIP.To4() != nil {
			return parsedIP.String()
		}
	}
	return ""
}

func GetIPV6(ips []corev1.PodIP) string {
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip.IP)
		if parsedIP.To4() == nil {
			return parsedIP.String()
		}
	}
	return ""
}
