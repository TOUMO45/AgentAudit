import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentaudit.layers.capability_graph import (  # noqa: E402
    analyze_capability_pairs,
    classify_tool,
)
from agentaudit.layers.static_graph import discover_tools  # noqa: E402

for p in ["fixtures/exfil/exfil_agent.py", "fixtures/exfil/exfil_hardened.py"]:
    print("=" * 68)
    print(p)
    tree = ast.parse(Path(p).read_text(encoding="utf-8"))
    for t in discover_tools(tree):
        print(f"   tool {t.name:22} caps={sorted(classify_tool(t))}")
    fs = analyze_capability_pairs(p)
    print(f"   -> {len(fs)} capability-pair finding(s)")
    for f in fs:
        md = f.metadata
        print(f"      [{f.severity.value:8}] {md['pattern']:20} "
              f"{md['tool_a']} + {md['tool_b']}")
        print(f"                 fingerprint={f.fingerprint}")
