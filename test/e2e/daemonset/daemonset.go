package daemonset

import (
	"context"
	"fmt"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

func GetDaemonSet(client *testclient.ClientSet, namespace, name string, timeout time.Duration) (*appsv1.DaemonSet, error) {
	var daemonSet appsv1.DaemonSet
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &daemonSet)
	return &daemonSet, err
}

func GetDaemonSetWithRetry(client *testclient.ClientSet, namespace, name string, retryInterval, timeout time.Duration) (*appsv1.DaemonSet, error) {
	var daemonSet *appsv1.DaemonSet
	err := wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		if daemonSet, err = GetDaemonSet(client, namespace, name, timeout); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, err
	})
	return daemonSet, err
}

func WaitForDaemonSetReady(client *testclient.ClientSet, ds *appsv1.DaemonSet, retryInterval, timeout time.Duration) error {
	err := wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		nCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		err = client.Get(nCtx, types.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}, ds)
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if ds.Status.DesiredNumberScheduled == ds.Status.NumberReady {
			return true, nil
		} else {
			return false, nil
		}
	})
	if err != nil {
		return fmt.Errorf("failed to wait for daemonset %s in namespace %s to be ready: %v", ds.Name, ds.Namespace, err)
	}

	return nil
}

func GetDaemonSetOnNode(client *testclient.ClientSet, namespace, nodeName string) (*corev1.Pod, error) {
	var podList *corev1.PodList
	err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
		podList, err = client.Pods(namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: "app=ingress-node-firewall-daemon",
			FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
		})

		if err != nil {
			return false, err
		}

		if len(podList.Items) == 1 {
			return true, nil
		}
		return false, nil
	})

	return &podList.Items[0], err
}
