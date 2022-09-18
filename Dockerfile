# Build the manager binary
FROM golang:1.18 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY pkg/ pkg/
COPY bindata/manifests/ bindata/manifests/

# Install libxdp and libbpf headers
ENV TOOLS_VERSION=1.2.6
ENV XDPTOOLS_SRC=/workspace/xdp-tools-$TOOLS_VERSION
# Packages to install via APT for building.
ENV BUILD_DEPS=" \
    clang llvm libelf-dev libpcap-dev gcc-multilib build-essential m4 \
    unzip \
    wget \
    libbpf-dev \
"
# install dependencies required for bulding libxdp lib
RUN apt-get update && apt -y install \
    ${BUILD_DEPS} && \
    rm -rf /var/lib/apt/lists/*

# Download libxdp source
RUN wget -O xdp-tools.tar.gz "https://github.com/xdp-project/xdp-tools/releases/download/v${TOOLS_VERSION}/xdp-tools-${TOOLS_VERSION}.tar.gz" \
    && tar xvfz xdp-tools.tar.gz \
    && rm -f xdp-tools.tar.gz

RUN cd $XDPTOOLS_SRC; ./configure; make install; cd $WORKDIR

# Build
RUN GOOS=linux GOARCH=amd64 go build -a -o manager main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /

COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/bindata/manifests /bindata/manifests

USER nonroot:nonroot

ENTRYPOINT ["/manager"]
