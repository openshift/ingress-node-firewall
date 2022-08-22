package pods

import (
	"bytes"
	"context"
	"io"
	"os"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecCommand runs command in the pod and returns buffer output
// copied entirely from SRIOV Network Operator
func ExecCommand(cs *testclient.ClientSet, pod *corev1.Pod, command ...string) (string, string, error) {
	var buf, errbuf bytes.Buffer
	req := cs.CoreV1Interface.RESTClient().
		Post().
		Namespace(pod.Namespace).
		Resource("pods").
		Name(pod.Name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: pod.Spec.Containers[0].Name,
			Command:   command,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cs.Config, "POST", req.URL())
	if err != nil {
		return buf.String(), errbuf.String(), err
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  os.Stdin,
		Stdout: &buf,
		Stderr: &errbuf,
		Tty:    true,
	})
	if err != nil {
		return buf.String(), errbuf.String(), err
	}

	return buf.String(), errbuf.String(), nil
}

// GetPodLogs returns the logs from container, or an error if the logs
// could not be fetched.
func GetPodLogs(clientset *testclient.ClientSet, pod *corev1.Pod, container string) (string, error) {
	req := clientset.Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: container})
	logStream, err := req.Stream(context.Background())
	if err != nil {
		return "", err
	}
	defer logStream.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, logStream); err != nil {
		return "", err
	}
	return buf.String(), nil
}
