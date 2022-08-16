#!/bin/bash

set -eu

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DAEMONSET_IMAGE=$1

if ! command -v yq ; then 
  echo "Could not find yq binary - trying to install it"
  go install github.com/mikefarah/yq/v4@latest
fi

if ! command -v yq ; then 
  echo "Cannot find command yq and could not install it."
  echo "Please modify file config/manager/env.yaml manually and point DAEMONSET_IMAGE to:"
  echo "    ${DAEMONSET_IMAGE}"
  exit 1
fi
yq e "(.spec.template.spec.containers[] | select(.name == \"manager\") .env[] | select(.name == \"DAEMONSET_IMAGE\") ).value=\"${DAEMONSET_IMAGE}\"" \
    -i ${DIR}/../config/manager/env.yaml
