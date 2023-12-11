# VERSION defines the project version for the bundle.
# Update this value when you upgrade the version of your project.
# To re-generate a bundle for another specific version without changing the standard setup, you can:
# - use the VERSION as arg of the bundle target (e.g make bundle VERSION=0.0.2)
# - use environment variables to overwrite this value (e.g export VERSION=0.0.2)
VERSION ?= 4.16.0
CSV_VERSION = $(shell echo $(VERSION) | sed 's/v//')
ifeq ($(VERSION), latest)
CSV_VERSION := 0.0.0
endif
CERT_MANAGER_VERSION=v1.9.1
IMAGE_ORG ?= $(USER)

# CHANNELS define the bundle channels used in the bundle.
# Add a new line here if you would like to change its default config. (E.g CHANNELS = "candidate,fast,stable")
# To re-generate a bundle for other specific channels without changing the standard setup, you can:
# - use the CHANNELS as arg of the bundle target (e.g make bundle CHANNELS=candidate,fast,stable)
# - use environment variables to overwrite this value (e.g export CHANNELS="candidate,fast,stable")
ifneq ($(origin CHANNELS), undefined)
BUNDLE_CHANNELS := --channels=$(CHANNELS)
endif

# DEFAULT_CHANNEL defines the default channel used in the bundle.
# Add a new line here if you would like to change its default config. (E.g DEFAULT_CHANNEL = "stable")
# To re-generate a bundle for any other default channel without changing the default setup, you can:
# - use the DEFAULT_CHANNEL as arg of the bundle target (e.g make bundle DEFAULT_CHANNEL=stable)
# - use environment variables to overwrite this value (e.g export DEFAULT_CHANNEL="stable")
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNELS) $(BUNDLE_DEFAULT_CHANNEL)

# IMAGE_TAG_BASE defines the docker.io namespace and part of the image name for remote images.
# This variable is used to construct full image tags for bundle and catalog images.
#
# For example, running 'make bundle-build bundle-push catalog-build catalog-push' will build and push both
# ingress-nodefw/ingress-node-firewall-bundle:$VERSION and ingress-nodefw/ingress-node-firewall-catalog:$VERSION.
IMAGE_TAG_BASE ?= quay.io/$(IMAGE_ORG)/ingress-nodefw/ingress-node-firewall

# BUNDLE_IMG defines the image:tag used for the bundle.
# You can use it as an arg. (E.g make bundle-build BUNDLE_IMG=<some-registry>/<project-name-bundle>:<tag>)
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)
# Default bundle index image tag
BUNDLE_INDEX_IMG ?= $(IMAGE_TAG_BASE)-index:v$(VERSION)
# BUNDLE_GEN_FLAGS are the flags passed to the operator-sdk generate bundle command
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)

# USE_IMAGE_DIGESTS defines if images are resolved via tags or digests
# You can enable this value if you would like to use SHA Based Digests
# To enable set flag to true
USE_IMAGE_DIGESTS ?= false
ifeq ($(USE_IMAGE_DIGESTS), true)
	BUNDLE_GEN_FLAGS += --use-image-digests
endif

# Image URL to use all building/pushing image targets
IMG ?= quay.io/openshift/origin-ingress-node-firewall:latest
DAEMON_IMG ?= quay.io/openshift/origin-ingress-node-firewall-daemon:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.25.2

# Default namespace
NAMESPACE ?= ingress-node-firewall-system

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

# CONTAINER_RUNNABLE determines if the tests can be run inside a container. It checks to see if
# podman/docker is installed on the system.
PODMAN ?= $(shell podman -v > /dev/null 2>&1; echo $$?)
ifeq ($(PODMAN), 0)
CONTAINER_RUNTIME=podman
else
CONTAINER_RUNTIME=docker
endif
CONTAINER_RUNNABLE ?= $(shell $(CONTAINER_RUNTIME) -v > /dev/null 2>&1; echo $$?)

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen generate-daemon-manifest ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	cp bundle/manifests/* manifests/stable

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS_DIR)/bin" go test ./... -coverprofile cover.out

.PHONY: test-race
test-race: manifests generate fmt vet envtest ## Run tests and check for race conditions.
	KUBEBUILDER_ASSETS="$(ENVTEST_ASSETS_DIR)/bin" go test -race ./...

.PHONY: create-kind-cluster 
create-kind-cluster: ## Create a kind cluster.
	hack/kind-cluster.sh

.PHONY: create-and-deploy-kind-cluster
create-and-deploy-kind-cluster: ## Create a kind cluster and deploy the operator.
	hack/kind-cluster.sh -d

.PHONY: destroy-kind-cluster 
destroy-kind-cluster: ## Destroy the kind cluster.
	kind delete cluster

ifdef WHAT
FOCUS = -ginkgo.focus "$(WHAT)"
endif
TESTS_REPORTS_PATH ?= /tmp/test_e2e_logs/
VALIDATION_TESTS_REPORTS_PATH ?= /tmp/test_validation_logs/
.PHONY: test-validation
test-validation: generate fmt vet manifests  ## Run validation tests
	rm -rf ${VALIDATION_TESTS_REPORTS_PATH}
	mkdir -p ${VALIDATION_TESTS_REPORTS_PATH}
	go test --tags=validationtests -v ./test/e2e/validation -ginkgo.v -junit $(VALIDATION_TESTS_REPORTS_PATH) -report $(VALIDATION_TESTS_REPORTS_PATH) $(FOCUS)

.PHONY: test-functional
test-functional: generate fmt vet manifests  ## Run functional tests
	rm -rf ${TESTS_REPORTS_PATH}
	mkdir -p ${TESTS_REPORTS_PATH}
	go test -timeout 20m --tags=e2etests -v ./test/e2e/functional -ginkgo.v -junit $(TESTS_REPORTS_PATH) -report $(TESTS_REPORTS_PATH) $(FOCUS)

.PHONY: test-e2e
test-e2e: generate fmt vet manifests test-validation test-functional  ## Run e2e tests. Limit scope with WHAT="<expression>".

##@ Build

.PHONY: build
build: prereqs generate fmt vet ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: podman-build
podman-build: ## Build podman image with the manager.
	podman build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}

.PHONY: podman-push
podman-push: ## Push podman image with the manager.
	podman push ${IMG}

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy-kind
deploy-kind: manifests kustomize install-cert-manager ## Deploy controller to the KinD cluster
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/kind | kubectl apply -f -

.PHONY: undeploy-kind
undeploy-kind: ## Undeploy controller from the KinD cluster. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/kind | kubectl delete --ignore-not-found=$(ignore-not-found) -f -
	kubectl delete -f $(CERT_MANAGER_URL)

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to OCP cluster.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/openshift | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the OCP cluster. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/openshift | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

CERT_MANAGER_URL ?= "https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml"

.PHONY: install-cert-manager
install-cert-manager: ## Install cert manager onto the target kubernetes cluster
	set -e ;\
	kubectl apply -f $(CERT_MANAGER_URL) ;\
	hack/wait_for_cert_manager.sh ;\

.PHONY: uninstall-cert-manager
uninstall-cert-manager: ## Uninstall cert manager from the target kubernetes cluster
	kubectl delete -f $(CERT_MANAGER_URL)

##@ Samples
.PHONY: deploy-samples
deploy-samples:  ## Deploy samples
	@echo "==== Label kind node to match nodeSelector"
	kubectl label node kind-worker do-node-ingress-firewall="true" --overwrite=true
	kubectl label node kind-worker2 do-node-ingress-firewall="true" --overwrite=true
	$(KUSTOMIZE) build config/samples | kubectl apply -f -

.PHONY: undeploy-samples
undeploy-samples: ## Undeploy samples
	kubectl label node kind-control-plane do-node-ingress-firewall="false" --overwrite=true
	$(KUSTOMIZE) build config/samples | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v3.8.7
CONTROLLER_TOOLS_VERSION ?= v0.9.0
OPERATOR_SDK_VERSION=v1.22.0

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	GOBIN=$(LOCALBIN) GOFLAGS="" go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	GOBIN=$(LOCALBIN)
	mkdir -p ${ENVTEST_ASSETS_DIR}
	test -f ${ENVTEST_ASSETS_DIR}/setup-envtest.sh || curl -sSLo ${ENVTEST_ASSETS_DIR}/setup-envtest.sh https://raw.githubusercontent.com/kubernetes-sigs/controller-runtime/v0.8.3/hack/setup-envtest.sh
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; fetch_envtest_tools $(ENVTEST_ASSETS_DIR); setup_envtest_env $(ENVTEST_ASSETS_DIR);

.PHONY: bundle
bundle: operator-sdk manifests kustomize ## Generate bundle manifests and metadata, then validate generated files.
	$(OPERATOR_SDK) generate kustomize manifests -q
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle $(BUNDLE_GEN_FLAGS)
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: ## Build the bundle image.
	docker build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: podman-bundle-build
podman-bundle-build: ## Build the bundle image with podman.
	podman build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push the bundle image.
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)

.PHONY: podman-bundle-push
podman-bundle-push: ## Push the bundle image with podman.
	$(MAKE) podman-push IMG=$(BUNDLE_IMG)

.PHONY: deploy-olm
deploy-olm: operator-sdk ## deploy OLM on the cluster.
	operator-sdk olm install --version $(OLM_VERSION)
	operator-sdk olm status

.PHONY: bundle-index-build
bundle-index-build: opm  ## Build the bundle index image.
	$(OPM) index add --bundles $(BUNDLE_IMG) --tag $(BUNDLE_INDEX_IMG) -c docker

.PHONY: podman-bundle-index-build
podman-bundle-index-build: opm  ## Build the bundle index image with podman.
	$(OPM) index add --bundles $(BUNDLE_IMG) --tag $(BUNDLE_INDEX_IMG) -c podman

.PHONY: build-and-push-bundle-images
build-and-push-bundle-images: docker-build docker-push  ## Generate and push bundle image and bundle index image.
	$(MAKE) bundle
	$(MAKE) bundle-build
	$(MAKE) docker-push IMG=$(BUNDLE_IMG)
	$(MAKE) bundle-index-build
	$(MAKE) docker-push IMG=$(BUNDLE_INDEX_IMG)

.PHONY: podman-build-and-push-bundle-images
podman-build-and-push-bundle-images: podman-build podman-push  ## Generate and push bundle image and bundle index image with podman.
	$(MAKE) bundle
	$(MAKE) podman-bundle-build
	$(MAKE) podman-push IMG=$(BUNDLE_IMG)
	$(MAKE) podman-bundle-index-build
	$(MAKE) podman-push IMG=$(BUNDLE_INDEX_IMG)

.PHONY: deploy-with-olm
deploy-with-olm: ## deploys the operator with OLM instead of manifests
	sed -i 's#quay.io/openshift/ingress-nodefw/ingress-node-firewall-index:.*#$(BUNDLE_INDEX_IMG)#g' config/olm-install/install-resources.yaml
	sed -i 's#ingress-node-firewall-system#$(NAMESPACE)#g' config/olm-install/install-resources.yaml
	$(KUSTOMIZE) build config/olm-install | kubectl apply -f -
	VERSION=$(CSV_VERSION) NAMESPACE=$(NAMESPACE) hack/wait-for-csv.sh

.PHONY: opm
OPM = ./bin/opm
opm: ## Download opm locally if necessary.
ifeq (,$(wildcard $(OPM)))
ifeq (,$(shell which opm 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(OPM)) ;\
	OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
	curl -sSLo $(OPM) https://github.com/operator-framework/operator-registry/releases/download/v1.23.0/$${OS}-$${ARCH}-opm ;\
	chmod +x $(OPM) ;\
	}
else
OPM = $(shell which opm)
endif
endif

PHONY: operator-sdk
operator-sdk: ## Get the current operator-sdk binary, If there isn't any, we'll use the GOBIN path.
ifeq (, $(shell which operator-sdk))
	@{ \
	set -e ;\
	curl -Lk  https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_linux_amd64 > $(GOBIN)/operator-sdk ;\
	chmod u+x $(GOBIN)/operator-sdk ;\
	}
OPERATOR_SDK=$(GOBIN)/operator-sdk
else
OPERATOR_SDK=$(shell which operator-sdk)
endif

.PHONY: generate-daemon-manifest
generate-daemon-manifest: ## Generate DaemonSet manifest.
	@echo "==== Generating DaemonSet manifest"
	hack/generate-daemon-manifest.sh

.PHONY: lint
lint: ## Run golangci-lint against code.
ifeq ($(CONTAINER_RUNNABLE), 0)
	@GOPATH=${GOPATH} ./hack/lint.sh $(CONTAINER_RUNTIME)
else
	echo "linter can only be run within a container since it needs a specific golangci-lint version"
endif

.PHONY: vendors
vendors: ## Updating vendors.
	go mod tidy && go mod vendor


# A comma-separated list of bundle images (e.g. make catalog-build BUNDLE_IMGS=example.com/operator-bundle:v0.1.0,example.com/operator-bundle:v0.2.0).
# These images MUST exist in a registry and be pull-able.
BUNDLE_IMGS ?= $(BUNDLE_IMG)

# The image tag given to the resulting catalog image (e.g. make catalog-build CATALOG_IMG=example.com/operator-catalog:v0.2.0).
CATALOG_IMG ?= $(IMAGE_TAG_BASE)-catalog:v$(VERSION)

# Set CATALOG_BASE_IMG to an existing catalog image tag to add $BUNDLE_IMGS to that image.
ifneq ($(origin CATALOG_BASE_IMG), undefined)
FROM_INDEX_OPT := --from-index $(CATALOG_BASE_IMG)
endif

# Build a catalog image by adding bundle images to an empty catalog using the operator package manager tool, 'opm'.
# This recipe invokes 'opm' in 'semver' bundle add mode. For more information on add modes, see:
# https://github.com/operator-framework/community-operators/blob/7f1438c/docs/packaging-operator.md#updating-your-existing-operator
.PHONY: catalog-build
catalog-build: opm ## Build a catalog image.
	$(OPM) index add --container-tool docker --mode semver --tag $(CATALOG_IMG) --bundles $(BUNDLE_IMGS) $(FROM_INDEX_OPT)

# Push the catalog image.
.PHONY: catalog-push
catalog-push: ## Push a catalog image.
	$(MAKE) docker-push IMG=$(CATALOG_IMG)

CILIUM_EBPF_VERSION := v0.11.0
GOLANGCI_LINT_VERSION = v1.46.2
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
GOOS ?= linux
LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest

##@ eBPF development
.PHONY: prereqs
prereqs: ## Check if prerequisites are met, and installing missing dependencies
	test -f $(shell go env GOPATH)/bin/golangci-lint || GOFLAGS="" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}
	test -f $(shell go env GOPATH)/bin/kind || go install sigs.k8s.io/kind@latest


# As generated artifacts are part of the code repo (pkg/ebpf and pkg/proto packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder or the
# protobuf definitions in the proto folder.
# You might want to use the docker-generate target instead of this.
.PHONY: ebpf-generate
ebpf-generate: export BPF_CLANG := $(CLANG)
ebpf-generate: export BPF_CFLAGS := $(CFLAGS)
ebpf-generate: prereqs ## Generating BPF Go bindings.
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...

.PHONY: docker-generate
docker-generate: ## Creating the container that generates the eBPF binaries
	docker build . -f hack/generators.Dockerfile -t $(LOCAL_GENERATOR_IMAGE)
	docker run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: ebpf-update-headers
ebpf-update-headers: ## eBPF update libbpf headers.
	hack/update-bfp-headers.sh

##@ Daemon development
.PHONY: daemon
daemon: ebpf-generate ## Build the daemon.
	hack/build-daemon.sh

.PHONY: docker-build-daemon
docker-build-daemon: ## Build the daemon image with docker. To change location, specify DAEMON_IMG=<image>.
	docker build -t ${DAEMON_IMG} -f Dockerfile.daemon .

.PHONY: docker-push-daemon
docker-push-daemon: ## Push the daemon image with docker. To change location, specify DAEMON_IMG=<image>.
	docker push ${DAEMON_IMG}

.PHONY: podman-build-daemon
podman-build-daemon: ## Build the daemon image with podman. To change location, specify DAEMON_IMG=<image>.
	podman build -t ${DAEMON_IMG} -f Dockerfile.daemon .

.PHONY: podman-push-daemon
podman-push-daemon: ## Push the daemon image with docker. To change location, specify DAEMON_IMG=<image>.
	podman push ${DAEMON_IMG}
