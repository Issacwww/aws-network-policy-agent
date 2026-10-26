# Decisions, grouped by what they change

This is a review record, not an approval log inferred from discussion. The user authorized the POC and these review drafts. That does not approve a production architecture or GA launch.

## Customer behavior and compatibility — review these first

| Decision | Current recommendation / constraint | Status and authority | Alternative and consequence | Delivery impact |
|---|---|---|---|---|
| D1a: endpoint compatibility | Keep existing PE/CPE schemas; old Auto continues, OSS Auto migration comes later | **ACCEPTED** by user for this project. Auto migration **PENDING TEAM APPROVAL** | Schema expansion was **SUPERSEDED** by this constraint; would require coordinated rollout | No coordinated Auto upgrade prerequisite; order provenance still needs a compatible solution |
| D1b: CNP rule order | Policy priority first, then original YAML rule order; first match wins | **PENDING TEAM APPROVAL**; user selected the working design | Action-based deny tie-break remains a review alternative; different customer behavior | Order-source proof before full CNP implementation. Standard NP/ANP retain additive allow semantics |
| D2b: resolver selection | Forward to the resolver addressed by that request | **ACCEPTED** explicitly by user | A fixed CoreDNS upstream was not selected: changes NodeLocal/custom resolver behavior | Both candidates must recover/preserve original destination; resolver trust is a separate decision |
| D3: expiry and active connections | POC revokes fresh connections. Recommend preserving established connections initially only if product/Auto approve and document it | **PROPOSED** | Revalidate established flows against generation/expiry: stronger revocation, datapath and state migration cost | Must settle before functional MVP acceptance; no silent weakening of R9 |
| D4: resolver trust | Admit grants only from an approved resolver boundary, without changing the chosen destination | **EXPLORING** | Trust every Pod-selected resolver: an attacker-controlled DNS server can mint arbitrary grants | AppSec/product decision early; endpoint inventory/config and DNS transport policy may be required |
| D5: metrics meaning | Export grant publication/state metrics; do not call unmatched DNS or an unattributable IP drop a domain denial | **PROPOSED** | Per-packet attribution requires datapath correlation; domain is still ambiguous for shared IPs | Product review of R19/R22 before observability implementation |
| D6: SG strict | Investigate; ship a documented limitation only with explicit support approval | **PROPOSED** | Full support may require preserving the Pod network/SG source on upstream forwarding | Potential separate adaptation work; cannot estimate until EKS tests |
| D7: enablement | Explicit opt-in POC; GA default-on only after supported CNI/controller/CRD rollout is defined | **PROPOSED** | Early default-on increases upgrade blast radius and exposes old-agent incompatibility | Add-on/schema owners must approve version floor and rollback behavior |

R4 order means the **rule list**, not creation time, API write order or informer arrival order. Neither referenced AWS blog proves the chosen same-policy ordering behavior. The internal implementation remains inaccessible.

## Technical choices — judge the evidence, not the mechanism's name

| Decision | Status | Recommendation basis | Other meaningful option | Consequence |
|---|---|---|---|---|
| D2a: interception | **PROPOSED** after local comparison; not user/team approved | Destination-aware DNAT for Service resolvers and TPROXY for other resolvers; see [POC report](poc-report.md) | Pure DNAT fails the tested NodeLocal NOTRACK path; pure TPROXY fails tested IPVS Service authorization | Adds resolver classification/configuration and updates to the EKS qualification gate |
| DNS interception at TC/eBPF | **REJECTED for this POC round**, explicitly by user | No demonstrated advantage justifying another interception implementation | May be revisited only with a concrete blocker and approval | Existing eBPF **enforcement remains in scope** |
| Production grant state | **PROPOSED** | Pod UID + policy revision + rule provenance in userspace; compiled aggregate in datapath | Direct last-answer-wins IP writes are smaller but lose overlapping TTL/port ownership | Common correctness work regardless of interception choice |
| Failure/restart | **PROPOSED** | Versioned publication and explicit recovery before readiness | Persist learned state: fewer DNS retries but validation/migration complexity | Launch gate; POC explicit cleanup is not a restart design |

Rejected/superseded options remain visible. If EKS or Auto evidence contradicts a constraint, flag it for review instead of silently modifying the accepted record. Detailed trade-offs and consequences are in the design; trivial code organization is not an approval item.
