#!/bin/bash

set -eux

REPO=github.com/openshift/ingress-node-firewall
WHAT=daemon
BIN_PATH=bin

GOFLAGS=${GOFLAGS:-}
LDFLAGS=${LDFLAGS:-}

# Set cross compilation flags and version override.
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
CGO_ENABLED=${CGO_ENABLED:-1}
if [ -z ${VERSION_OVERRIDE+a} ]; then
    echo "Using version from git..."
    VERSION_OVERRIDE=$(git describe --abbrev=8 --dirty --always)
fi
LDFLAGS+="-X ${REPO}/pkg/version.Version=${VERSION_OVERRIDE}"

# Go to the root of the repo and create bin if it does not exist.
cdup="$(git rev-parse --show-cdup)" && test -n "$cdup" && cd "$cdup"
mkdir -p ${BIN_PATH}

# Build the binary.
CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} go build ${GOFLAGS} -ldflags "${LDFLAGS} -s -w" -o ${BIN_PATH}/${WHAT} cmd/${WHAT}.go
