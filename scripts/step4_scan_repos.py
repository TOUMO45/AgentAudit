"""Step 4 — clone public strands-agents repos (read-only), run Layer 2 static
trust-graph analysis, collect findings for hand-verification.

No AWS. No execution of any cloned code. Static AST parsing only.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.layers import static_graph  # noqa: E402
from agentaudit.layers.capability_graph import analyze_capability_pairs  # noqa: E402

WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("_step4_repos")
WORK.mkdir(exist_ok=True)

REPOS = [
    "https://github.com/martimfasantos/ai-agents-frameworks",
    "https://github.com/kyopark2014/strands-agent",
    "https://github.com/aal80/agentcore-samples",
    "https://github.com/strands-rl/strands-sglang",
    "https://github.com/Amagash/sample-building-ai-agents-with-strands",
    "https://github.com/LondheShubham153/strands-agents-workshop",
    "https://github.com/aleck31/Sandbox-on-EC2",
    "https://github.com/awsdataarchitect/costco-price-match",
    "https://github.com/aws-samples/sample-agentic-ai-factory",
]


def clone(url: str) -> Path | None:
    name = url.rstrip("/").split("/")[-1]
    dest = WORK / name
    if dest.exists():
        return dest
    r = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        print(f"  clone FAILED {name}: {r.stderr.strip()[:120]}")
        return None
    return dest


def head_commit(path: Path) -> str:
    r = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip()[:12]


def is_strands_agent_file(text: str) -> bool:
    return ("from strands import" in text or "import strands" in text) and "@tool" in text


results = []
for url in REPOS:
    name = url.rstrip("/").split("/")[-1]
    print(f"\n=== {name} ===")
    dest = clone(url)
    if not dest:
        continue
    commit = head_commit(dest)
    py_files = [p for p in dest.rglob("*.py")
                if ".venv" not in p.parts and "site-packages" not in p.parts
                and "node_modules" not in p.parts]
    scanned = 0
    for pf in py_files:
        try:
            text = pf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not is_strands_agent_file(text):
            continue
        scanned += 1
        rel = pf.relative_to(dest).as_posix()
        try:
            findings = static_graph.analyze(str(pf))
            findings += analyze_capability_pairs(str(pf))
        except SyntaxError as e:
            print(f"  {rel}: SYNTAX ERROR ({e})")
            continue
        for f in findings:
            results.append({
                "repo": name, "url": url, "commit": commit,
                "file": rel, "line": f.line,
                "detector": f.detector, "severity": f.severity.value,
                "title": f.title, "evidence": f.evidence,
                "metadata": f.metadata,
            })
            print(f"  [{f.severity.value.upper():8}] {f.detector:30} {rel}:{f.line}")
    print(f"  strands agent files scanned: {scanned}")

Path("references/_step4_raw_findings.json").write_text(
    json.dumps(results, indent=2), encoding="utf-8"
)
print(f"\n{'='*60}")
print(f"repos processed: {len(REPOS)}   raw findings: {len(results)}")
print("-> references/_step4_raw_findings.json")
