#!/usr/bin/env python3
"""Run all candidates in one already-created experiment cluster, preserving failures."""

import argparse, subprocess, pathlib, json

p = argparse.ArgumentParser()
p.add_argument("name")
p.add_argument("kubeconfig")
p.add_argument("output_dir")
p.add_argument(
    "--modes",
    nargs="+",
    default=["dnat", "tproxy", "hybrid"],
    choices=["dnat", "tproxy", "hybrid"],
)
a = p.parse_args()
assert a.name.startswith("dns-poc-")
root = pathlib.Path(__file__).resolve().parent
out = pathlib.Path(a.output_dir).resolve()
out.mkdir(parents=True, exist_ok=True)
subprocess.run(
    ["kind", "load", "docker-image", "dns-policy-poc:local", "--name", a.name],
    check=True,
)
for mode in a.modes:
    name = a.name.removeprefix("dns-poc-") + "-" + mode
    subprocess.run(
        ["python3", str(root / "switch.py"), a.name, a.kubeconfig, mode], check=True
    )
    with (out / (name + ".log")).open("w") as log:
        r = subprocess.run(
            [
                "python3",
                str(root / "check.py"),
                "--name",
                a.name,
                "--kubeconfig",
                a.kubeconfig,
                "--output",
                str(out / (name + ".json")),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    print(name, "suite exit", r.returncode, flush=True)
    with (out / (name + "-nodelocal.log")).open("w") as log:
        subprocess.run(
            [
                "python3",
                str(root / "nodelocal.py"),
                a.name,
                a.kubeconfig,
                str(out / (name + "-nodelocal.json")),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    k = ["kubectl", "--context", "kind-" + a.name, "--kubeconfig", a.kubeconfig]
    metadata = {}
    for key, args in {
        "kernel": ["docker", "exec", a.name + "-control-plane", "uname", "-a"],
        "image": [
            "docker",
            "image",
            "inspect",
            "dns-policy-poc:local",
            "--format",
            "{{.Id}}",
        ],
        "pods": k + ["get", "pods", "-n", "dns-poc", "-o", "wide"],
        "kube_proxy_config": k
        + [
            "get",
            "cm",
            "kube-proxy",
            "-n",
            "kube-system",
            "-o",
            "jsonpath={.data.config\\.conf}",
        ],
        "kube_proxy_logs": k
        + ["logs", "ds/kube-proxy", "-n", "kube-system", "--tail=40"],
        "owned_rules": [
            "docker",
            "exec",
            a.name + "-control-plane",
            "nft",
            "list",
            "table",
            "ip",
            "dns_policy_poc",
        ],
        "routes": ["docker", "exec", a.name + "-control-plane", "ip", "rule", "show"],
    }.items():
        x = subprocess.run(
            args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        metadata[key] = x.stdout
    (out / (name + "-environment.json")).write_text(
        json.dumps(metadata, indent=2) + "\n"
    )
