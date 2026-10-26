#!/usr/bin/env python3
"""Switch experiments only in a disposable kind node; never use on EKS."""

import argparse, subprocess, time, pathlib

p = argparse.ArgumentParser()
p.add_argument("name")
p.add_argument("kubeconfig")
p.add_argument("mode", choices=["dnat", "tproxy", "hybrid"])
a = p.parse_args()
assert a.name.startswith("dns-poc-")
k = ["kubectl", "--context", "kind-" + a.name, "--kubeconfig", a.kubeconfig]


def run(args, **kw):
    return subprocess.run(args, check=True, **kw)


run(k + ["delete", "ds", "npa", "-n", "dns-poc", "--ignore-not-found"])
run(
    k
    + ["wait", "--for=delete", "pod", "-l", "app=npa", "-n", "dns-poc", "--timeout=90s"]
)
run(
    [
        "docker",
        "exec",
        a.name + "-control-plane",
        "sh",
        "-c",
        "nft delete table ip dns_policy_poc 2>/dev/null || true; ip addr del 169.254.29.53/32 dev lo 2>/dev/null || true; ip rule del priority 1053 fwmark 0x20000000/0x20000000 lookup 2053 2>/dev/null || true; ip route del local 0.0.0.0/0 dev lo table 2053 2>/dev/null || true",
    ]
)
s = (
    pathlib.Path(__file__)
    .with_name("stack.yaml")
    .read_text()
    .replace("value: dnat", "value: " + a.mode)
)
if a.mode == "hybrid":
    svc = subprocess.check_output(
        k
        + [
            "get",
            "svc",
            "resolver",
            "-n",
            "dns-poc",
            "-o",
            "jsonpath={.spec.clusterIP}",
        ],
        text=True,
    )
    s = s.replace(
        "- name: AWS_EC2_METADATA_SERVICE_ENDPOINT",
        '- name: DNS_POLICY_DNAT_RESOLVERS\n          value: "'
        + svc
        + '"\n        - name: AWS_EC2_METADATA_SERVICE_ENDPOINT',
    )
run(k + ["apply", "-f", "-"], input=s, text=True)
run(k + ["rollout", "status", "ds/npa", "-n", "dns-poc", "--timeout=120s"])
time.sleep(5)
run(
    [
        "python3",
        str(pathlib.Path(__file__).with_name("attach.py")),
        a.name,
        a.kubeconfig,
    ]
)
run(k + ["apply", "-f", str(pathlib.Path(__file__).with_name("policies.yaml"))])
time.sleep(3)
