"""Phase 5 verification: UI-served Cedar text must byte-match the file on disk."""

import json
import sys
import urllib.request
from pathlib import Path

api = json.loads(urllib.request.urlopen("http://127.0.0.1:8770/api/policies").read())
ok = True
print(f"policies served by API: {api.get('count', 0)}")
for p in api["policies"]:
    disk = Path(p["file"]).read_text(encoding="utf-8")
    match = disk == p["cedar"]
    ok = ok and match
    print(f"\n  {p['policy_name']}")
    print(f"    file        : {p['file']}")
    print(f"    status      : {p['status']}")
    print(f"    disk bytes  : {len(disk)}   api bytes: {len(p['cedar'])}")
    print(f"    BYTE-MATCH  : {'YES' if match else 'NO'}")

print("\n" + "=" * 60)
print("ALL POLICIES MATCH DISK" if ok else "MISMATCH DETECTED")
sys.exit(0 if ok else 1)
