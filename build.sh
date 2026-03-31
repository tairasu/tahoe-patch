#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

mode="${1:-release}"
case "$mode" in
  release|debug) ;;
  *)
    echo "Usage: $0 [release|debug]"
    exit 1
    ;;
esac

make "$mode"
echo "Built: $(pwd)/bin/tahoe-patch"
file "$(pwd)/bin/tahoe-patch"
