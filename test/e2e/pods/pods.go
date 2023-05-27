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
	podutil "k8s.io/kubernetes/pkg/api/v1/pod"
	"k8s.io/utils/pointer"
)

func EnsureRunning(client *testclient.ClientSet, pod *corev1.Pod, namespace string,
	retryInterval, timeout time.Duration) (*corev1.Pod, error) {
	var testPod *corev1.Pod
	created, err := client.Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, err
		}
	}

	err = wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		testPod, err = client.Pods(namespace).Get(context.Background(), created.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if testPod.Status.Phase == corev1.PodRunning && podutil.IsPodReady(testPod) {
			return true, nil
		}
		return false, nil
	})
	return testPod, err
}

func EnsureDeleted(client *testclient.ClientSet, pod *corev1.Pod, retryInterval, timeout time.Duration) error {
	err := client.Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{GracePeriodSeconds: pointer.Int64(0)})
	if err != nil {
		return err
	}
	err = wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		_, err = client.Pods(pod.Namespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	return err
}

func EnsureDeletedWithLabel(client *testclient.ClientSet, ns, label string, retryInterval, timeout time.Duration) error {
	podList, err := client.Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: label,
	})
	if err != nil {
		return err
	}
	for _, pod := range podList.Items {
		if err = EnsureDeleted(client, &pod, retryInterval, timeout); err != nil {
			return err
		}
	}
	return nil
}

func GetPodWithLabelRestartCount(client *testclient.ClientSet, namespace, label string, timeout time.Duration) (int, error) {
	podList, err := client.Pods(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: label})
	if err != nil {
		return 0, err
	}
	var count int
	for _, pod := range podList.Items {
		for _, containerStatus := range pod.Status.ContainerStatuses {
			count += int(containerStatus.RestartCount)
		}
	}
	return count, nil
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
