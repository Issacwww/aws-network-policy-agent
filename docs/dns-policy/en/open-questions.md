# Questions that could change the plan

| Question | Smallest useful validation | Owner / effect |
|---|---|---|
| Does the selected transport preserve DNS behavior on actual VPC CNI ENIs? | Run the same packet/permission tests on a disposable EKS AL2023 node; capture both DNS legs and check host firewall/mark ownership | NPA + VPC CNI; prerequisite to any EKS-supported claim |
| Can NodeLocal coexist in all supported topologies? | Local-IP topology is tested here; add Service-IP co-binding, multiple upstreams and resolver restart on EKS | NPA; affects interception and reply implementation |
| Is upstream node identity allowed under SG standard/strict? | DNS allowed only through the Pod SG, denied through node SG; inspect branch ENI path and query source | VPC CNI/SG owners; may change forwarding placement or support matrix |
| Where does CNP rule order come from without schema changes? | Trace two swapped rules through generation, chunking and NPA compilation; if lost, prototype read-only original-CNP correlation with revision checks | Controller + NPA; additional informer/RBAC work if required |
| What does Auto do at TTL zero, deletion, shared IP and existing connections? | Run a shared black-box conformance fixture on internal Auto; preserve outputs and exact versions | Auto/product; cannot be inferred from port PR |
| What is an authorized DNS resolver? | Confirm tenant model and DNS transport policy ownership; demonstrate malicious resolver returning an unrelated sensitive IP | AppSec/product; defines whether DNS responses are an authorization authority |
| Which versions install/update ANP CRDs and enable the feature? | Validate clean install, CNI upgrade, rollback and mixed-node behavior with add-on owners | CNI/controller release owners; determines minimum version, not a guessed number |
| What are safe CPU/memory and outage budgets? | Dense-node sustained DNS load, saturation and pause/restart tests on target hardware | NPA/oncall; sets bounds/readiness and rollout thresholds |

Threat-model assumptions were submitted to the user for confirmation. Until answered, the threat model is a **conditional review draft**, not a signed-off security assessment. Estimates in the milestone draft explicitly depend on these questions.
