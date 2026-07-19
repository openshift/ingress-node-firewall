#!/usr/bin/env bash

set -euo pipefail

VERSION=v2.3.1
if [ "$#" -ne 1 ]; then
    echo "Expected command line argument - container runtime (docker/podman) got $# arguments: $@"
    exit 1
fi

USERNS_FLAG=""
[[ "$1" == "podman" ]] && USERNS_FLAG="--userns=keep-id"

$1 run --security-opt label=disable --rm $USERNS_FLAG -v $(pwd):/app -w /app -e GO111MODULE=on docker.io/library/golang:1.26.0 \
	bash -c "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${VERSION} && \
	golangci-lint run --verbose \
	--timeout=15m0s" && \
	echo "lint OK!"
