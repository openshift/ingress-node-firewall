#!/bin/bash
set -euo pipefail

MANIFEST_FILE="daemonset.yaml"
MANIFEST_PATH="bindata/manifests/daemon"
MANIFEST="${MANIFEST_PATH}/${MANIFEST_FILE}"

# Use temp file approach for cross-platform compatibility
# (sed -i behavior differs between GNU sed on Linux and BSD sed on macOS)
TEMP_FILE=$(mktemp)
trap 'rm -f "${TEMP_FILE}"' EXIT

# This ensures the daemon container image field is set to {{.Image}}
if ! sed "s|image:.*|image: '{{.Image}}'|g" "${MANIFEST}" > "${TEMP_FILE}"; then
    echo "Error: Failed to substitute image in ${MANIFEST}" >&2
    exit 1
fi

# Replace original file
if ! mv "${TEMP_FILE}" "${MANIFEST}"; then
    echo "Error: Failed to update ${MANIFEST}" >&2
    exit 1
fi
