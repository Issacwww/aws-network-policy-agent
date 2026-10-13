# S1 Test Diff Code Review

## Review scope

- **Fact:** One `/code-review` subagent reviewed all test, stub, and document changes with emphasis on false-red, false-green, and R1-R15 coverage.
- **Fact:** The reviewer compiled `test/integration/clusternetworkpolicy`; after review, the suite was also run serially against the original NPA cluster.

## Findings and disposition

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | Major | `ValidateRules` tested a synthetic helper instead of the ANP/CNP CEL boundary. | **Fixed.** Removed the helper and unit test. Added a cluster CRD admission assertion that `domainNames` with `Deny` is rejected. PE/CPE envtest remains the NPA-side handoff test; upstream controller generation is outside this repository. |
| 2 | Major | `PlanRedirect` could be implemented in isolation and false-green R2/R14. | **Fixed.** Replaced the boolean planner with a `SyncPod` contract that consumes `DomainRuleStore` and records concrete `RedirectRuleManager.Add` interactions, including the host veth, original-destination requirement, and hook priority. The stub still returns only `ErrNotImplemented`. |
| 3 | Major | Passing the original resolver directly into `SelectUpstream` does not prove kernel redirect metadata preserved it. | **Rejected for this layer.** T-04 intentionally freezes the mechanism-independent `OriginalDestination` contract. Kernel retrieval is mechanism-specific; S1 freezes the deployed redirect ordering in the R14 cluster assertion instead of inventing an unimplemented kernel boundary. |
| 4 | Major | R5 injected `Matched` directly and did not exercise query-match-to-writer flow. | **Fixed.** `ProcessResponse` now receives a fake matcher and fake cache writer; tests assert the original query name is matched and only matching responses write every A record. |
| 5 | Major | One RR per TTL subtest could pass if the first TTL were applied to every address. | **Fixed.** One response now contains four distinct A records with TTL 1, 30, 300, and 0; expiry is asserted per IP, with zero mapped to 300 seconds. |
| 6 | Major | Expiry helper was not connected to eBPF and did not test refresh on the next query. | **Partially fixed; local eBPF portion rejected.** Added a second-query refresh test and retained deterministic new-connection expiry boundaries. Local `BPF_PROG_TEST_RUN` is infeasible (`EPERM`, no effective capabilities); cluster dataplane leaves ran, but original NPA failed before domain-derived ipcache behavior became observable. |
| 7 | Major | R9 did not freeze the `priority*10+action` ABI or Baseline offset. | **Fixed.** Added red assertions for Admin p50 Accept `501`, Admin p10 Deny `100`, and Baseline p10 Accept `20101`, plus both verdict regressions. |
| 8 | Major | The Baseline cluster regression did not first prove the Baseline domain allow was effective. | **Fixed.** A fresh pod avoids stale Admin ipcache state; a Baseline p100 CIDR deny control proves Baseline p10 domain access first, then an independent namespace deny-all requires persistent DROP. |
| 9 | Major | A single eventual Admin failure could false-green on a transient timeout. | **Fixed.** The test first waits for enforcement and then requires failures consistently across independent `wget` connections. |
| 10 | Major | R12 checked only the number of ports. | **Fixed.** Assertions now verify protocol, `Port`, `EndPort`, numeric TCP/80, and TCP/8000-8100 independently. |
| 11 | Major | The flag test did not verify parsed state reached configuration. | **Fixed.** Added the allowed minimal `ControllerConfig.EnableDNSPolicy` type stub and asserted parsing `true` sets it; no binding logic was implemented, so the test remains red. |
| 12 | Major | The CEL cluster test accepted any API error as proof that `Deny` was rejected. | **Fixed.** It now requires `apierrors.IsInvalid`, unwraps `APIStatus`, and checks validation causes mention both `domainNames` and `Accept`. |
| 13 | Major | R5 did not prove both distinct A records or the matched rule reached the writer. | **Fixed.** The test checks each expected IP exactly once and compares every `CacheWrite.Rule` with the matcher result. |
| 14 | Major | R7 could still pass if the same first IP were written four times. | **Fixed.** Per-IP occurrence counts must now equal one in addition to independent expiry assertions. |
| 15 | Major | Refresh bypassed the matcher/writer chain and did not freeze the absence of active requery. | **Fixed.** Two application responses traverse `ProcessResponse` into a stateful writer. A `Proxy` contract with a counting upstream also holds the count constant past TTL expiry and refreshes only on the next application query. |
| 16 | Major | Baseline could be contaminated by the earlier Admin FQDN/IP cache. | **Fixed.** Baseline uses a fresh pod plus a separate Service, FQDN, and ClusterIP before adding its namespace deny-all. |
| 17 | Minor | The cluster flag helper rejected valid bare `--enable-dns-policy`. | **Fixed.** It now accepts bare bool syntax, `--flag=true`, and `--flag true`, while rejecting explicit false. |
| 18 | Major | R2 could branch on `PodIdentifier` text without consulting the domain-rule store. | **Fixed.** Positive and negative cases use the same identifier, and the fake records exactly one `HasAnyDomainRules` lookup with that key. |
| 19 | Major | R7 still lacked an observable no-active-requery assertion. | **Fixed.** A thread-safe counting forwarder must remain at one call beyond TTL expiry and reach two only after the second explicit application query. |
| 20 | Major | Namespace deny-all also blocked DNS, so FQDN failure did not prove it overrode Baseline ipcache. | **Fixed.** The test first proves a direct Service-IP connection succeeds from the prewarmed domain entry, then applies namespace deny-all and requires new direct-IP connections to fail consistently. |
| 21 | Major | The feature-disabled R2 case required a store lookup, rejecting a valid feature-first short circuit. | **Fixed.** Store key/count is required only when the feature is enabled; the disabled control requires only zero redirect calls. |
| 22 | Major | The first real cluster run stopped the `Ordered` container after the expected R10 red, so both R9 leaves were skipped. | **Fixed.** Added `ContinueOnFailure` and an Admin positive domain precondition. The second serial run executed all seven S1 leaves; both R9 leaves red at their positive domain precondition on original NPA, rather than false-passing a deny assertion. |
| 23 | Major | `FINDINGS.md` and previously captured evidence still described cluster tests as compile-only after the real run. | **Fixed.** Updated the living end-state documents with the 7-spec, 2-pass/5-red result, R9 prerequisite limitation, cleanup result, and recaptured cluster evidence. |

## Remaining limitations

- **Fact:** R2/R3 production call sites do not exist on `origin/main`; the new interfaces are contract stubs only, and POC-1 behavior is the evidence that the assertions can turn green.
- **Fact:** Both R9 cluster leaves execute, but original NPA lacks the prerequisite domain allow behavior, so the lower-priority deny steps remain unreachable until that base feature exists.
