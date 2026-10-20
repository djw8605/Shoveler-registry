#!/bin/sh
# Seal secret.env into sealed-secret.yaml for the tiger cluster's
# sealed-secrets controller. Only the sealed file is committed.
#
#   ./seal-secret.sh /path/to/tiger-osg-config/tiger-cert.pem [secret.env]
#
# Uses the tiger certificate offline: no cluster login needed. A sealed
# secret only decrypts in the namespace it was sealed for (NAMESPACE, default
# osg), so reseal if the overlay's namespace changes.
set -eu

cert=${1:?usage: $0 /path/to/tiger-cert.pem [secret.env]}
dir=$(cd "$(dirname "$0")" && pwd)
env_file=${2:-$dir/secret.env}
namespace=${NAMESPACE:-osg}

if grep -q REPLACE_ME "$env_file"; then
    echo "$env_file still contains REPLACE_ME values" >&2
    exit 1
fi

kubectl create secret generic shoveler-auth-portal \
    --namespace "$namespace" --dry-run=client \
    --from-env-file="$env_file" -o json \
  | kubeseal --cert "$cert" -o yaml > "$dir/sealed-secret.yaml"

echo "Wrote $dir/sealed-secret.yaml (namespace $namespace)"
