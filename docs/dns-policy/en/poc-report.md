# POC results: interception is not the same as authorization

**Recommendation: take the destination-aware DNAT + TPROXY combination into EKS validation.** Keep the two pure candidates as diagnostic controls. Neither pure candidate covered both Service DNS and real NodeLocal DNSCache in all three local kube-proxy modes. The combination is an experimental recommendation, not proof of EKS support or a production-ready implementation.

The POC intentionally uses the real policy controller, real PE resources, NPA and its eBPF enforcement. A successful DNS response alone is not a pass: the selected Pod must subsequently reach the application while the other Pod and wrong port remain denied.

## 1. Measured comparison

The final matrix is generated from the accompanying JSON evidence. “Service suite” means 20 checks covering UDP/TCP DNS, immediate application access, per-Pod and port restrictions, TTL expiry, case/exact/wildcard matching and policy deletion. All application lifetime checks use **fresh connections**.

| kube-proxy | Candidate | Service suite | NodeLocal UDP: DNS / app | NodeLocal TCP: DNS / app |
|---|---|---|---|---|
| iptables | dnat | 20/20 | PASS / FAIL | PASS / FAIL |
| iptables | tproxy | 20/20 | PASS / PASS | PASS / PASS |
| iptables | hybrid | 20/20 | PASS / PASS | PASS / PASS |
| ipvs | dnat | 20/20 | PASS / FAIL | PASS / FAIL |
| ipvs | tproxy | 15/20 | PASS / PASS | PASS / PASS |
| ipvs | hybrid | 20/20 | PASS / PASS | PASS / PASS |
| nftables | dnat | 20/20 | PASS / FAIL | PASS / FAIL |
| nftables | tproxy | 20/20 | PASS / PASS | PASS / PASS |
| nftables | hybrid | 20/20 | PASS / PASS | PASS / PASS |

NodeLocal results use its **local-address topology** at `169.254.20.10`, forwarding to the fixture Service. The test waits for installed NOTRACK rules, not just a Ready Pod. Service-IP co-binding, other node images and other Kubernetes versions are not certified by this test.

An additional check removed DNS transport permission while retaining domain rules. All 12 checks (Service/NodeLocal × UDP/TCP × three modes) were denied, confirming that the combined POC does not automatically allow DNS. See `*-no-auto-dns.json`.

## 2. What explains the results

**DNAT works for tracked Service DNS.** The destination becomes the proxy's local address. TCP recovers the original destination with SO_ORIGINAL_DST; UDP uses conntrack in this experiment. Returning UDP from the translated local address is essential for reverse NAT. The implementation uses IP_PKTINFO to choose it. Its full conntrack-table lookup is a diagnostic shortcut, not a scalable production approach.

**NodeLocal exposes the DNAT limitation.** Its NOTRACK rules mean the query can reach NodeLocal and resolve successfully without traversing the DNAT proxy. Application access then remains denied because no DNS grant was learned. This occurred after confirming the real node-cache rules. An earlier run before those rules appeared was discarded as an invalid compatibility result.

**TPROXY needs more than a listener.** Scoped client-leg NOTRACK prevents subsequent kube-proxy NAT from breaking transparent TCP. UDP replies must use the original resolver source; binding a new socket to NodeLocal's port 53 conflicts with its existing listener. The POC sends checksummed raw IPv4 UDP replies instead, requiring NET_RAW. Upstream forwarding remains node-originated TCP to the original resolver.

**IPVS is a separate interception obstacle.** In the tested Service path, DNS resolves but TPROXY does not produce the application grant. Linux IPVS registers its input hook before final socket delivery and can consume a Service destination despite earlier transparent interception. The [Linux 6.10 implementation](https://github.com/torvalds/linux/blob/v6.10/net/netfilter/ipvs/ip_vs_core.c#L1911) supports that explanation; the packet-path consequence is measured by the negative authorization checks. NodeLocal's non-Service address works in the same mode.

**The combination uses each mechanism on a path it can handle.** `DNS_POLICY_DNAT_RESOLVERS` explicitly lists tracked Service resolver addresses. Those queries use DNAT; other resolver addresses use TPROXY. The same socket layer distinguishes translated destinations from transparent ones, and both call the same policy/answer handler. No additional DNS authorization implementation was introduced.

This is still not a universal topology solution. A stale Service list, a NodeLocal listener co-binding the Service IP, or a new unlisted IPVS resolver can invalidate the split. Production needs authoritative classification and update handling. The next EKS experiment must establish those conditions, not merely repeat kind's fixed fixture.

## 3. Exactly what was built

- Replaced the port's fixed-upstream proxy manager with explicit `dnat`, `tproxy` and diagnostic `hybrid` opt-in modes. The combined experiment was added only after the two-candidate comparison exposed complementary failures.
- Preserved original resolver destinations, bounded concurrent handlers, supported UDP/TCP clients, and used TCP upstream with deadlines. UDP answers respect client size bounds; malformed/mismatched responses do not authorize traffic.
- Validated reachable CNAME/A answer data, bounded chain TTL, skipped zero-TTL grants, and waited for successful map writes before returning matching answers. Unrelated/additional records are ignored.
- Used full Pod-name identities in the experiment, normalized domain case, added conservative normal-path cache invalidation on policy changes, rejected map-rule overflow and aligned expiry clock with the datapath's monotonic clock.
- Added disposable kind provisioning, real controller/agent fixtures, actual node-cache tests, reproducible result capture and Linux-run unit tests. The underlying DNS eBPF path comes from PR #3 and is not reclassified as upstream or Auto evidence.

Source entry points: [interception](../../../pkg/proxymanager/proxymanager.go), [socket transport](../../../pkg/dnsproxy/server_linux.go), [answer/policy barrier](../../../pkg/dnsproxy/handler.go), [grant writer](../../../pkg/ebpf/bpf_client.go#L722), [tests/runbook](../../../test/dns-policy-poc/README.md).

## 4. Environment and evidence boundaries

| Item | Value |
|---|---|
| Test date | 2026-10-26 |
| Kubernetes / kind | 1.35.0 / 0.31.0 |
| Node image | `kindest/node@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f` |
| Linux runtime | Docker Desktop LinuxKit 6.10.14, ARM64 |
| NodeLocal | `registry.k8s.io/dns/k8s-dns-node-cache:1.27.1`, pulled digest `sha256:6748acde83ac08626a27a554da5364e8cac64bc950c6a1b6b939a3d27b364ae7` |
| Agent image | See per-candidate `*-environment.json` for exact content hash |
| Source baselines | [Verified system model](system-understanding.md) |

[evidence/](evidence/) contains the final test results and configuration/kernel/image provenance, including failed pure-candidate checks. The ordinary-NetworkPolicy kindnet collision and intermediate implementation failures were diagnosed before this final run; they are not counted as candidate results. No performance benchmark was performed. Per-query timings in dig output are diagnostics, not comparative latency claims.

The Go checks cover DNS answer filtering, SERVFAIL, UDP checksum/truncation and existing filter/utils/controller/RPC tests. eBPF programs were compiled and loaded on the test kernel. This does not substitute for fault injection, kernel/OS certification or upstream CI.

## 5. What the next engineer should not infer

This branch is a transferable POC, **not a release candidate**. It does not prove full CNP precedence/order; overlapping names/ports can still overwrite one IP entry; multi-address publication is not atomic; invalidation errors are not fully propagated; workload identity is not yet Pod-UID/generation safe; restart ownership/recovery is incomplete; cleanup is conservative and manual after a crash. Existing connections may outlive expiry/deletion. Zero-TTL usability and authoritative resolver trust need explicit product/AppSec decisions.

The DNAT conntrack scan, global grant lock, per-Pod map size, fixed mark/address/route resources, raw UDP reply path, TCP-only upstream and broad test image privileges are deliberate experimental constraints. They need replacement or validation before scale/GA. Metrics R19–R22 are not implemented. IPv6, Bottlerocket, SG modes, real EKS ENIs and internal Auto are untested.

Keep PE/CPE schemas unchanged. Keep current Auto agents running. No production-default enablement or minimum supported CNI version is asserted. Follow the [internal EKS handoff](../../../test/dns-policy-poc/README.md#what-to-carry-to-an-internal-eks-workstation) and the [milestone gates](milestones.md), then revisit the recommendation with actual AWS evidence.
