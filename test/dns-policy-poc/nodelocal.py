#!/usr/bin/env python3
import argparse, pathlib, subprocess, time, json

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


svc = run(
    ["get", "svc", "resolver", "-o", "jsonpath={.spec.clusterIP}"], check=True
).stdout
target = run(
    ["get", "pod", "resolver", "-o", "jsonpath={.status.podIP}"], check=True
).stdout
manifest = (
    pathlib.Path(__file__)
    .with_name("nodelocal.yaml")
    .read_text()
    .replace("__UPSTREAM__", svc)
)
print(run(["apply", "-f", "-"], input=manifest, check=True).stdout)
print(run(["rollout", "status", "ds/nodelocal", "--timeout=90s"], check=True).stdout)
# Readiness alone does not prove that NodeLocal installed its NOTRACK rules.
for attempt in range(90):
    raw = subprocess.check_output(
        ["docker", "exec", a.name + "-control-plane", "iptables-save", "-t", "raw"],
        text=True,
    )
    if "169.254.20.10/32" in raw and "NOTRACK" in raw:
        break
    time.sleep(1)
else:
    raise RuntimeError("NodeLocal NOTRACK missing; test inconclusive")
run(["apply", "-f", str(pathlib.Path(__file__).with_name("policies.yaml"))], check=True)
time.sleep(7)
results = []
for tcp in [False, True]:
    r = run(
        [
            "exec",
            "allowed",
            "--",
            "dig",
            "@169.254.20.10",
            "api.poc.test",
            "+time=2",
            "+tries=1",
        ]
        + (["+tcp"] if tcp else [])
    )
    h = run(
        [
            "exec",
            "allowed",
            "--",
            "curl",
            "--noproxy",
            "*",
            "-fsS",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            f"http://{target}:8080/",
        ]
    )
    results.append(
        {
            "transport": "tcp" if tcp else "udp",
            "dns_ok": r.returncode == 0 and "status: NOERROR" in r.stdout,
            "application_allowed": h.returncode == 0,
            "dns_output": r.stdout,
            "application_output": h.stdout,
        }
    )
    print(results[-1], flush=True)
    time.sleep(7)
raw = subprocess.run(
    ["docker", "exec", a.name + "-control-plane", "iptables-save", "-t", "raw"],
    text=True,
    stdout=subprocess.PIPE,
).stdout
pathlib.Path(a.output).write_text(
    json.dumps(
        {
            "cluster": a.name,
            "tests": results,
            "raw_rules": raw,
            "logs": run(["logs", "ds/nodelocal"]).stdout,
        },
        indent=2,
    )
    + "\n"
)
