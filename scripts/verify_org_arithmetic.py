"""Phase 2 verification (live): org totals must equal the sum of per-agent counts."""

import json
import sys
import urllib.request

state = json.loads(urllib.request.urlopen("http://127.0.0.1:8770/api/state").read())
org = state["org"]
assert org["state"] == "live", f"org view not live: {org}"

print(f"agents scanned: {org['agent_count']}   total findings: {org['total_findings']}")
print()
hdr = f"{'agent':44} {'crit':>5}{'high':>6}{'med':>5}{'low':>5}{'info':>6}"
print(hdr)
print("-" * len(hdr))
for agent, c in org["per_agent"].items():
    print(f"{agent:44} {c['critical']:>5}{c['high']:>6}{c['medium']:>5}{c['low']:>5}{c['info']:>6}")
print("-" * len(hdr))
t = org["totals"]
print(f"{'TOTALS (reported)':44} {t['critical']:>5}{t['high']:>6}{t['medium']:>5}{t['low']:>5}{t['info']:>6}")

ok = True
for sev in ("critical", "high", "medium", "low", "info"):
    expected = sum(c[sev] for c in org["per_agent"].values())
    match = expected == t[sev]
    ok = ok and match
    print(f"  assert totals[{sev:8}] == sum(per_agent) -> {t[sev]} == {expected}  {'OK' if match else 'FAIL'}")

sum_all = sum(t.values())
print(f"  assert total_findings == sum(totals)      -> {org['total_findings']} == {sum_all}  "
      f"{'OK' if org['total_findings'] == sum_all else 'FAIL'}")
ok = ok and org["total_findings"] == sum_all

# per-agent findings must be distinct, not duplicated across agents
files = {a: {f["location"] for f in s["findings"]} for a, s in state["scans"].items()}
agents = list(files)
distinct = True
for i, a in enumerate(agents):
    for b in agents[i + 1:]:
        if files[a] and files[b] and files[a] & files[b]:
            distinct = False
            print(f"  DUPLICATE findings shared between {a} and {b}")
print(f"  assert findings are per-agent distinct    -> {'OK' if distinct else 'FAIL'}")
ok = ok and distinct

print("\n" + "=" * 60)
print("ORG AGGREGATION VERIFIED" if ok else "ARITHMETIC MISMATCH")
sys.exit(0 if ok else 1)
