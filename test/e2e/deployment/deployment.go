package deployment

import (
	"context"
	"fmt"
	"time"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

func GetDeployment(client *testclient.ClientSet, namespace, name string, timeout time.Duration) (*appsv1.Deployment, error) {
	var deployment appsv1.Deployment
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &deployment)
	return &deployment, err
}

func GetDeploymentWithRetry(client *testclient.ClientSet, namespace, name string, retryInterval, timeout time.Duration) (*appsv1.Deployment, error) {
	var deployment *appsv1.Deployment
	err := wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		if deployment, err = GetDeployment(client, namespace, name, timeout); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})

	return deployment, err
}

func WaitForDeploymentSetReady(client *testclient.ClientSet, deployment *appsv1.Deployment, retryInterval,
	timeout time.Duration) error {

	err := wait.PollUntilContextTimeout(context.Background(), retryInterval, timeout, true, func(ctx context.Context) (done bool, err error) {
		nCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		err = client.Get(nCtx, types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, deployment)
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		if *deployment.Spec.Replicas == deployment.Status.ReadyReplicas {
			return true, nil
		} else {
			return false, nil
		}
	})
	if err != nil {
		return fmt.Errorf("failed to wait for deployment %s in namespace %s to be ready: %v", deployment.Name,
			deployment.Namespace, err)
	}

	return nil
}
