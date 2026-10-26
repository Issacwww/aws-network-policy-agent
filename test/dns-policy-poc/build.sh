#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
controller_source=${1:?Usage: build.sh /path/to/controller-at-65a296e}
expected=65a296e580b827b323b53be461ff46b768ba34d4
[[ $(git -C "$controller_source" rev-parse HEAD) == "$expected" ]] || { echo "Controller must be at $expected" >&2; exit 1; }
case $(docker info --format '{{.Architecture}}') in
 aarch64|arm64) arch=arm64;; x86_64|amd64) arch=amd64;; *) echo 'Unsupported Docker architecture' >&2;exit 1;;
esac
mkdir -p test/dns-policy-poc/build
build_dir="$PWD/test/dns-policy-poc/build"
docker build -t dns-policy-poc-tools:local -f test/dns-policy-poc/Dockerfile.tools .
export GOOS=linux GOARCH=$arch CGO_ENABLED=0
go build -o "$build_dir/controller" .
go build -o "$build_dir/adapter" ./test/dns-policy-poc/adapter
go build -o "$build_dir/fixture" ./test/dns-policy-poc/fixture
(cd "$controller_source" && go build -o "$build_dir/policy-controller" ./cmd)
docker run --rm --privileged -v "$PWD:/work" -w /work dns-policy-poc-tools:local sh -c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/c/vmlinux.h && make build-bpf ARCH=$arch"
cp pkg/ebpf/c/tc.v{4,6}{ingress,egress}.bpf.o pkg/ebpf/c/v{4,6}events.bpf.o "$build_dir/"
docker build -t dns-policy-poc:local -f test/dns-policy-poc/Dockerfile .
