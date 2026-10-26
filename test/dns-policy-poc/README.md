# DNS interception comparison — experimental, IPv4 only

This is a **real NPA/PE/eBPF authorization test** on disposable kind clusters. It is not an EKS conformance suite or production deployment manifest. Read the [report](../../docs/dns-policy/en/poc-report.md) before interpreting green DNS queries as successful policy enforcement.

## Build and reproduce

Prerequisites: Docker Linux engine with privileged containers, kind 0.31, kubectl, Python 3 and the Go toolchain specified by this repository. Docker Desktop supplies Linux on macOS. Budget several GB of memory per active experiment; run clusters sequentially on a constrained machine. The tools image contains nftables/iproute2, BPF build tooling and diagnostics. No host TPROXY daemon is needed.

Obtain a clean controller checkout at the pinned revision; do not reset a working checkout containing changes:

```sh
git clone https://github.com/aws/amazon-network-policy-controller-k8s /tmp/dns-poc-controller-source
git -C /tmp/dns-poc-controller-source checkout --detach 65a296e580b827b323b53be461ff46b768ba34d4
./test/dns-policy-poc/build.sh /tmp/dns-poc-controller-source
python3 test/dns-policy-poc/create.py iptables /tmp/dns-poc-controller-source /tmp/dns-poc-run
python3 test/dns-policy-poc/matrix.py dns-poc-iptables /tmp/dns-poc-run/dns-poc-iptables.kubeconfig /tmp/dns-poc-run/evidence
```

Repeat `create.py` and `matrix.py` with `ipvs` and `nftables`. Use unique disposable `dns-poc-*` clusters; creation refuses a pre-existing kind cluster. The scripts always use an explicit kubeconfig/context and never deploy to the current context. `matrix.py` deliberately retains negative candidate results; inspect the JSON `pass` fields rather than treating script completion as all-pass. NodeLocal tests require actual NOTRACK rules before proceeding; absence is inconclusive, not a pass.

To test only the proposed combination:

```sh
python3 test/dns-policy-poc/matrix.py dns-poc-iptables /tmp/dns-poc-run/dns-poc-iptables.kubeconfig /tmp/dns-poc-run/evidence --modes hybrid
```

The controller converts ANPs into real PEs. `adapter/` only substitutes EC2 metadata and ipamd configuration/ADD RPCs. `attach.py` renames kind veths to the VPC CNI naming convention and invokes the real NPA ADD RPC. `fixture/` answers test DNS with its own address (TTL 5) and serves HTTP on 8080/8081. `check.py` verifies new connections before/after learning, per-Pod/port scope, matching, expiry and deletion. `nodelocal.py` uses the actual Kubernetes node-cache image, forwarding to that fixture. Both UDP and TCP client DNS use TCP on the upstream leg in this POC.

Use ANP, not ordinary NP, for the fixture: new kind has an independent ordinary-NetworkPolicy enforcer that would not know AWS domain grants. This avoids double enforcement; production NP/ANP interoperability remains a separate test gate.

Unit tests run inside Linux even when Go cross-compiles on macOS:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -exec "$PWD/test/dns-policy-poc/linux-exec.sh" ./pkg/dnsproxy ./pkg/filter ./pkg/utils ./pkg/proxymanager ./controllers ./pkg/rpc
```

Use `GOARCH=amd64` for an x86 Docker engine. The runtime image is built for the Docker engine's architecture, not necessarily the host Go process architecture.

## What to carry to an internal EKS workstation

Carry this branch/PR and the pinned controller reference. Build `dns-policy-poc:local` on the target architecture and publish it to your approved internal test registry. **Do not apply `stack.yaml`, the cluster-admin binding or the metadata adapter on EKS.** They are kind-only fixtures.

On an isolated EKS test node group, preserve the actual VPC CNI DaemonSet's network namespace, mounts, lifecycle RPC and existing sidecar arguments. Override the NPA container image and command to `/controller`, retaining `--enable-network-policy=true` and the relevant existing agent flags. The image carries the BPF objects and the real agent. Use explicit opt-in environment:

```yaml
env:
- name: DNS_POLICY_INTERCEPTION
  value: hybrid
- name: DNS_POLICY_DNAT_RESOLVERS
  value: "<actual-DNS-Service-IPv4-address>"
```

`dnat` and `tproxy` remain available for comparison. Leave the variable absent for feature-off. Legacy `dns-policy-upstream-*`/priority flags inherited from the port do not control this experiment. Do not use them to select an upstream: it comes from the original destination. IPv6 opt-in exits with an error.

Before running: confirm the deployed controller produces domain PEs and compatible CRDs; do not install a second competing policy controller. Verify `NET_ADMIN`/`NET_RAW`, transparent sockets and netfilter modules, `nft`/`ip` execution, BPFFS mount, availability of UDP/TCP 50052, local address `169.254.29.53`, mark `0x20000000`, rule priority `1053` and route table `2053`. The POC does not implement general collision resolution. Keep NodeLocal's address out of the DNAT list; Service-IP co-binding requires further investigation. A Service address change requires explicit reconfiguration/restart in this POC.

Then reproduce the fixture behavior with real Pod lifecycle and packet captures. Specifically test node-originated upstream DNS against Pod/node SG rules. **Local success does not establish that no EKS code change will be needed.** The next engineer should first close EKS integration and topology evidence, not enable this in a shared production node group.

## Cleanup and failure behavior

For kind, `switch.py` waits for the old NPA Pod to disappear and removes only this experiment's table/address/routing objects. It does not flush kube-proxy, NodeLocal or all netfilter/BPF state. The agent refuses a pre-existing experiment table rather than guessing ownership after a crash. This is a POC limitation; production restart recovery is unfinished.

Delete only the clusters created for the experiment:

```sh
kind delete cluster --name dns-poc-iptables
kind delete cluster --name dns-poc-ipvs
kind delete cluster --name dns-poc-nftables
```

On EKS, use the previous image/config and a reviewed, node-scoped cleanup plan. Merely removing the env variable is not a validated rollback: pinned state and interception resources can survive an unclean exit. Keep a recovery path to the node and follow the design's launch gates.
