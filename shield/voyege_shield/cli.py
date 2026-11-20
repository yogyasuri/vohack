"""`voyege-diagnose <url>` — read-only site posture scan from the terminal."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .diagnose import LiveDiagnostic

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser(description="Voyege read-only web posture diagnostic")
    ap.add_argument("url", help="target URL, e.g. https://staging.example.com")
    ap.add_argument("-y", "--authorized", action="store_true",
                    help="confirm you own or are authorised to test this target (required)")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    a = ap.parse_args()
    if not a.authorized:
        sys.exit("Refused. Re-run with -y to confirm you are authorised to test this target.\n"
                 "Only point Voyege at systems you own or are authorised to test.")
    policy = yaml.safe_load((ROOT / "config/policy.yaml").read_text())
    owners = yaml.safe_load((ROOT / "config/owners.yaml").read_text())
    diag = LiveDiagnostic(policy, ROOT / "data", owners)
    res = diag.scan(a.url, authorized=True)
    if a.json:
        print(json.dumps(res, indent=2, default=str))
        return
    s = res["summary"]
    print(f"\n  Voyege posture scan · {res['target']}")
    print(f"  HTTPS: {'yes' if res['https'] else 'NO'} · findings: "
          f"{s['High']} high / {s['Medium']} medium / {s['Low']} low · "
          f"{len(res['inventory'])} routes seen · recorder chain {'ok' if res['recorder']['ok'] else 'BROKEN'}\n")
    for f in res["findings"]:
        print(f"  [{f['severity']:<6}] {f['title']}")
        print(f"           {f['detail']}")
        print(f"           fix: {f['fix']}\n")
    if res["routes_from_js"]:
        print("  Routes discovered in front-end JS:")
        for r in res["routes_from_js"][:20]:
            print(f"    - {r}")
    print(f"\n  {res['note']}")


if __name__ == "__main__":
    main()
