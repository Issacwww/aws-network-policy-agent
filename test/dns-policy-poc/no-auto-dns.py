#!/usr/bin/env python3
"""Domain permissions must not create permission to query DNS."""

import argparse, json, pathlib, subprocess, time

p = argparse.ArgumentParser()
p.add_argument("name")
p.add_argument("kubeconfig")
p.add_argument("output")
a = p.parse_args()
assert a.name.startswith("dns-poc-")
k = [
    "kubectl",
    "--context",
    "kind-" + a.name,
    "--kubeconfig",
    a.kubeconfig,
    "-n",
    "dns-poc",
]


def run(args, **kw):
    return subprocess.run(
        k + args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw
    )


policy = str(pathlib.Path(__file__).with_name("policies.yaml"))
results = []
try:
    run(["apply", "-f", policy], check=True)
    run(
        [
            "patch",
            "applicationnetworkpolicy",
            "transport-only",
            "--type=merge",
            "-p",
            json.dumps({"spec": {"egress": []}}),
        ],
        check=True,
    )
    time.sleep(3)
    svc = run(
        ["get", "svc", "resolver", "-o", "jsonpath={.spec.clusterIP}"], check=True
    ).stdout
    for resolver in [svc, "169.254.20.10"]:
        for transport in ["udp", "tcp"]:
            r = run(
                [
                    "exec",
                    "allowed",
                    "--",
                    "dig",
                    "@" + resolver,
                    "api.poc.test",
                    "+time=1",
                    "+tries=1",
                ]
                + (["+tcp"] if transport == "tcp" else [])
            )
            results.append(
                {
                    "resolver": resolver,
                    "transport": transport,
                    "pass": r.returncode != 0,
                    "output": r.stdout,
                }
            )
finally:
    run(["apply", "-f", policy], check=True)
pathlib.Path(a.output).write_text(
    json.dumps({"cluster": a.name, "tests": results}, indent=2) + "\n"
)
raise SystemExit(0 if len(results) == 4 and all(x["pass"] for x in results) else 1)
