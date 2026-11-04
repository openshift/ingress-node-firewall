# Build the manager binary
FROM golang:1.26 as builder

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

# Fix permissions for bindata manifests
RUN chmod -R a+r bindata/manifests

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o manager main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder --chown=65532:65532 /workspace/manager .
COPY --from=builder --chown=65532:65532 /workspace/bindata/manifests /bindata/manifests

USER 65532:65532

ENTRYPOINT ["/manager"]
