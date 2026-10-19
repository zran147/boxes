#!/usr/bin/env bash
# Per-recipe registry CI: lint + harness + sandboxed verification + signed
# attestation + publish to a static registry.
#
#   scripts/registry-ci.sh RECIPE_DIR REGISTRY_DIR PUBLISHER PRIVATE_KEY \
#       [OPERATOR_KEY] [OS] [ATTESTATION_DIR]
#
# Container PoCs use the locked Docker sandbox; VM PoCs use the isolated QEMU
# profile (pre-bake that OS first). Run `boxes proxy up` before container
# verification.
set -euo pipefail

recipe_dir=$(realpath "${1:?recipe dir}")
registry_dir=${2:?registry dir}
publisher=${3:?publisher}
key=${4:?private key}
operator=${5:-$key}
oses=${6:-ubuntu-22.04}
att_dir=${7:-attestations}

root=$(dirname "$recipe_dir")
recipe_id=$(python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["id"])' "$recipe_dir/recipe.yaml")
version=$(python3 -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1]))["version"])' "$recipe_dir/recipe.yaml")
poc_backend=$(python3 -c 'import sys, yaml; d=yaml.safe_load(open(sys.argv[1])); print("vm" if "vm" in (d.get("poc") or {}) else "container")' "$recipe_dir/recipe.yaml")
poc_context=$(python3 -c 'import sys, yaml; d=yaml.safe_load(open(sys.argv[1])); print((d.get("poc") or {}).get("context", "target"))' "$recipe_dir/recipe.yaml")
if [ "$poc_backend" = "vm" ]; then
    backend=qemu
    if [ "$poc_context" = "attacker" ]; then
        sandbox=trusted
    else
        sandbox=isolated
    fi
else
    backend=docker
    sandbox=locked
fi

# Keep installed registry recipes out of this local verification.
export BOXES_REGISTRY_DIR="${BOXES_REGISTRY_DIR:-$(mktemp -d)}"

echo "== lint =="
boxes --recipes "$root" lint

echo "== harness: $recipe_id =="
boxes --recipes "$root" test-recipe "$recipe_id"

attestations=()
for os in $oses; do
    echo "== sandboxed verification: $recipe_id ($os, $backend/$sandbox) =="
    boxes --recipes "$root" verify --recipe "$recipe_id" --os "$os" \
        --backend "$backend" --sandbox "$sandbox" --no-cache \
        --attest-key "$key" --attestation-dir "$att_dir"
    attestation="$att_dir/$recipe_id-$version-$os-$poc_backend-$sandbox.json"
    attestations+=(--attestation "$attestation")
done

echo "== publish =="
boxes registry publish "$recipe_dir" \
    --registry-dir "$registry_dir" \
    --publisher "$publisher" \
    --key "$key" \
    --operator-key "$operator" \
    "${attestations[@]}"
