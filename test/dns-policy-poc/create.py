#!/usr/bin/env python3
"""Create one disposable cluster; does not read or mutate the current context."""

import argparse, pathlib, subprocess, time

p = argparse.ArgumentParser()
p.add_argument("mode", choices=["iptables", "ipvs", "nftables"])
p.add_argument("controller_source")
p.add_argument("output_dir")
a = p.parse_args()
root = pathlib.Path(__file__).resolve().parent
out = pathlib.Path(a.output_dir).resolve()
out.mkdir(parents=True, exist_ok=True)
name = "dns-poc-" + a.mode
kube = out / (name + ".kubeconfig")
config = out / (name + ".yaml")
config.write_text(
    "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnetworking:\n  kubeProxyMode: "
    + a.mode
    + "\nnodes:\n- role: control-plane\n"
)


def run(args):
    subprocess.run([str(x) for x in args], check=True)


run(
    [
        "kind",
        "create",
        "cluster",
        "--name",
        name,
        "--kubeconfig",
        kube,
        "--config",
        config,
        "--image",
        "kindest/node@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f",
        "--wait",
        "120s",
    ]
)
run(
    [
        "docker",
        "exec",
        name + "-control-plane",
        "mount",
        "-t",
        "bpf",
        "bpf",
        "/sys/fs/bpf",
    ]
)
run(["kind", "load", "docker-image", "dns-policy-poc:local", "--name", name])
k = ["kubectl", "--context", "kind-" + name, "--kubeconfig", kube]
run(k + ["apply", "-f", pathlib.Path(a.controller_source) / "config/crd/bases"])
run(k + ["apply", "-f", root / "stack.yaml"])
run(
    k
    + [
        "wait",
        "--for=condition=Ready",
        "pod",
        "--all",
        "-n",
        "dns-poc",
        "--timeout=120s",
    ]
)
time.sleep(5)
run(["python3", root / "attach.py", name, kube])
run(k + ["apply", "-f", root / "policies.yaml"])
time.sleep(3)
print("READY:", name, kube)
