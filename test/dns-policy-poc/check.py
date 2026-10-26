#!/usr/bin/env python3
"""Black-box checks: real DNS, real PE reconciliation, real eBPF enforcement."""

import argparse, json, subprocess, time, pathlib

p = argparse.ArgumentParser()
p.add_argument("--name", required=True)
p.add_argument("--kubeconfig", required=True)
p.add_argument("--output", required=True)
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


def cmd(args):
    return subprocess.run(
        k + args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )


def ip(kind, name, field):
    return cmd(["get", kind, name, "-o", "jsonpath={" + field + "}"]).stdout


resolver = ip("svc", "resolver", ".spec.clusterIP")
target = ip("pod", "resolver", ".status.podIP")
results = []


def check(name, args, good=True, contains=None):
    r = cmd(args)
    ok = (r.returncode == 0) == good and (contains is None or contains in r.stdout)
    results.append(
        {"name": name, "pass": ok, "exit": r.returncode, "output": r.stdout.strip()}
    )
    print(name, "PASS" if ok else "FAIL", r.stdout.strip(), flush=True)


def dns(name, query, tcp=False):
    check(
        name,
        ["exec", "allowed", "--", "dig", "@" + resolver, query, "+time=2", "+tries=1"]
        + (["+tcp"] if tcp else []),
        contains="status: NOERROR",
    )


def http(name, pod, port=8080, good=True):
    check(
        name,
        [
            "exec",
            pod,
            "--",
            "curl",
            "--noproxy",
            "*",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            "-fsS",
            f"http://{target}:{port}/",
        ],
        good,
    )


http("before DNS denied", "allowed", good=False)
dns("UDP DNS original resolver", "api.poc.test")
http("domain allows selected Pod", "allowed")
http("port restriction", "allowed", 8081, False)
http("other Pod denied", "blocked", good=False)
time.sleep(6)
http("TTL expiry denies fresh connection", "allowed", good=False)
dns("TCP DNS original resolver", "api.poc.test", True)
http("TCP DNS grant", "allowed")
time.sleep(6)
dns("case insensitive", "API.POC.TEST")
http("case grant", "allowed")
time.sleep(6)
dns("deep wildcard", "a.b.wild.poc.test")
http("wildcard grant", "allowed")
time.sleep(6)
dns("wildcard bare domain resolves", "wild.poc.test")
http("wildcard excludes bare domain", "allowed", good=False)
dns("unmatched DNS still resolves", "other.poc.test")
http("unmatched gives no grant", "allowed", good=False)
dns("grant before delete", "api.poc.test")
http("grant before delete works", "allowed")
check("delete policy", ["delete", "applicationnetworkpolicy", "domains"])
time.sleep(1)
http("policy deletion revokes fresh connection", "allowed", good=False)
pathlib.Path(a.output).write_text(
    json.dumps(
        {"cluster": a.name, "resolver": resolver, "target": target, "tests": results},
        indent=2,
    )
    + "\n"
)
raise SystemExit(0 if all(x["pass"] for x in results) else 1)
