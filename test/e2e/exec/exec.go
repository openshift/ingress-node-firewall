package exec

import (
	"bytes"
	"io"
	"os"

	testclient "github.com/openshift/ingress-node-firewall/test/e2e/client"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// ExecCommand runs command in the pod and returns buffer output
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

// ExecCommandWithStdin runs a command in the a pod and also injects a string to stdin.
func ExecCommandWithStdin(cs *testclient.ClientSet, pod *corev1.Pod, stdin string, command ...string) (string, string, error) {
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
		return "", "", err
	}

	reader, writer := io.Pipe()
	go func() {
		defer writer.Close()
		buf := bytes.NewBufferString(stdin)
		_, _ = io.Copy(writer, buf)
	}()
	var stdout, stderr bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  reader,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	return stdout.String(), stderr.String(), nil
}
