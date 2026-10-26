#!/bin/sh
set -eu
binary=$1
shift
docker run --rm -v "$(dirname "$binary"):/test:ro" -v "$PWD:/src:ro" -w /src dns-policy-poc-tools:local "/test/$(basename "$binary")" "$@"
