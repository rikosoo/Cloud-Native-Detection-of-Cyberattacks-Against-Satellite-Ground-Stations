#!/usr/bin/env bash
# Build the Lambda layer that carries the gsd package and its dependencies.
#
#   ./infra/build_layer.sh            # -> build/gsd-layer.zip
#
# Runs pip against the manylinux target so numpy ships the right wheel for the
# Lambda runtime regardless of the machine building it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${ROOT}/build/layer"
OUT="${ROOT}/build/gsd-layer.zip"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"

rm -rf "${BUILD}" "${OUT}"
mkdir -p "${BUILD}/python"

python3 -m pip install \
  --quiet \
  --target "${BUILD}/python" \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version "${PYTHON_VERSION}" \
  --only-binary=:all: \
  numpy PyYAML

cp -r "${ROOT}/src/gsd" "${BUILD}/python/gsd"
find "${BUILD}/python" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "${BUILD}/python" -name '*.dist-info' -type d -prune -exec rm -rf {} +

mkdir -p "$(dirname "${OUT}")"
(cd "${BUILD}" && zip -qr "${OUT}" python)
echo "built ${OUT} ($(du -h "${OUT}" | cut -f1))"
