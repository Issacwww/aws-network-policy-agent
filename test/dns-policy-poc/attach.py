#!/usr/bin/env python3
"""Kind-only: name host veths as VPC CNI does, then issue its real NPA ADD RPC.
Run only against a disposable dns-poc-* cluster. No datapath or policy mocks.
"""

import hashlib, json, subprocess, sys

name = sys.argv[1]
if not name.startswith("dns-poc-"):
    raise SystemExit("refusing non-experiment cluster")
kube = [
    "kubectl",
    "--context",
    "kind-" + name,
    "--kubeconfig",
    sys.argv[2],
    "-n",
    "dns-poc",
]


def out(args):
    return subprocess.check_output(args, text=True).strip()


node = name + "-control-plane"
npa = json.loads(out(kube + ["get", "pods", "-l", "app=npa", "-o", "json"]))["items"][
    0
]["metadata"]["name"]
for pod in ["allowed", "blocked"]:
    idx = out(kube + ["exec", pod, "--", "cat", "/sys/class/net/eth0/iflink"])
    links = json.loads(out(["docker", "exec", node, "ip", "-j", "link"]))
    iface = next(x["ifname"] for x in links if str(x["ifindex"]) == idx)
    expected = "eni" + hashlib.sha1(("dns-poc." + pod).encode()).hexdigest()[:11]
    if iface != expected:
        subprocess.run(
            ["docker", "exec", node, "ip", "link", "set", iface, "name", expected],
            check=True,
        )
    subprocess.run(
        kube + ["exec", npa, "--", "/adapter", "enforce", pod, "dns-poc"], check=True
    )
