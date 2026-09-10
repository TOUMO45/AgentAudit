"""AgentAudit command-line interface.

    agentaudit run   --agent fixtures/vulnerable_agent.py [--deploy-config f.json]
                     [--out DIR] [--no-dynamic] [--live-role ROLE] [--region R]
                     [--fail-on {any,critical,high,medium}]
    agentaudit verify --json report.signed.json
    agentaudit dashboard [--port 8770] [--no-open]

Exit code follows the signed JSON so the tool drops straight into a CI gate:
non-zero means the agent failed the policy (charter success condition 1).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentaudit import __version__
from agentaudit.audit import run_audit
from agentaudit.models import Severity
from agentaudit.report import renderer

_FAIL_RANK = {
    "any": Severity.INFO.rank,
    "medium": Severity.MEDIUM.rank,
    "high": Severity.HIGH.rank,
    "critical": Severity.CRITICAL.rank,
}


def _should_fail(card, fail_on: str) -> bool:
    threshold = _FAIL_RANK[fail_on]
    return any(f.severity.rank >= max(threshold, 1) for f in card.findings)


def _cmd_run(args: argparse.Namespace) -> int:
    agent = args.agent
    if not Path(agent).exists():
        print(f"error: agent file not found: {agent}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    card = run_audit(
        agent,
        deploy_config=args.deploy_config,
        enable_dynamic=not args.no_dynamic,
        live_role=args.live_role,
        region=args.region,
        raw_out=str(out_dir / "cloud_raw.json") if args.live_role else None,
    )

    json_path = out_dir / "report.signed.json"
    sarif_path = out_dir / "report.sarif"
    html_path = out_dir / "scorecard.html"
    aibom_path = out_dir / "aibom.json"
    renderer.render_json(card, str(json_path))
    renderer.render_sarif(card, str(sarif_path))
    renderer.render_html(card, str(html_path))

    from agentaudit.aibom import render_aibom

    render_aibom(agent, str(aibom_path), deploy_config=args.deploy_config)

    _print_summary(card, out_dir)

    failed = _should_fail(card, args.fail_on)
    return 1 if failed else 0


def _print_summary(card, out_dir: Path) -> None:
    bar = "=" * 64
    print(bar)
    print(f" AgentAudit v{card.tool_version}  --  {card.agent_path}")
    print(bar)
    for lr in card.layer_reports:
        mark = {"ran": "[RAN]", "skipped": "[SKIP]", "error": "[ERR]"}.get(lr.status, "[?]")
        print(f" {mark:<7} {lr.layer.value:<14} {lr.detail}")
    print(bar)
    counts = card.counts_by_severity()
    print(
        f" GRADE {card.grade}  |  risk {card.score}/100  |  "
        f"{counts['critical']} critical / {counts['high']} high / "
        f"{counts['medium']} medium / {counts['low']} low"
    )
    print(bar)
    from agentaudit.taxonomy import asi_2026

    for f in card.findings:
        asi = asi_2026.label_for(f.detector)
        tag = f" [{asi}]" if asi else ""
        print(f"  [{f.severity.value.upper():<8}] {f.detector}{tag}  {f.location}")
        print(f"             {f.title}")
    if not card.findings:
        print("  clean -- no findings")
    print(bar)
    print(f" reports: {out_dir/'scorecard.html'} · {out_dir/'report.sarif'} · "
          f"{out_dir/'report.signed.json'} · {out_dir/'aibom.json'}")
    print(bar)


def _cmd_verify(args: argparse.Namespace) -> int:
    import json

    from agentaudit import signing

    payload = json.loads(Path(args.json).read_text(encoding="utf-8"))
    ok = signing.verify(payload)
    print(f"signature: {'VALID' if ok else 'INVALID / TAMPERED'}")
    return 0 if ok else 1


def _cmd_dashboard(args: argparse.Namespace) -> int:
    """Start the stdlib HTTP server and open a browser to it (never file://)."""
    from agentaudit.dashboard.server import serve

    return serve(host=args.host, port=args.port, open_browser=args.open_browser)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentaudit", description="Security audit for Strands agents.")
    p.add_argument("--version", action="version", version=f"agentaudit {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="audit a Strands agent")
    run.add_argument("--agent", required=True, help="path to the agent .py file")
    run.add_argument("--deploy-config", help="AgentCore deploy descriptor (JSON); else auto-discovered")
    run.add_argument("--out", default="out", help="output directory for reports (default: out/)")
    run.add_argument("--no-dynamic", action="store_true", help="skip the dynamic red-team (static only)")
    run.add_argument("--live-role", help="IAM role name for a live read-only cloud-posture check")
    run.add_argument("--region", help="AWS region for live checks")
    run.add_argument(
        "--fail-on", choices=list(_FAIL_RANK), default="medium",
        help="minimum severity that makes the run fail (default: medium)",
    )
    run.set_defaults(func=_cmd_run)

    verify = sub.add_parser("verify", help="verify a signed JSON report")
    verify.add_argument("--json", required=True, help="path to report.signed.json")
    verify.set_defaults(func=_cmd_verify)

    dash = sub.add_parser("dashboard", help="serve the live web dashboard over HTTP")
    dash.add_argument("--port", type=int, default=8770)
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--open", dest="open_browser", action="store_true", default=True,
                      help="open a browser to the dashboard (default)")
    dash.add_argument("--no-open", dest="open_browser", action="store_false",
                      help="do not open a browser (headless / CI use)")
    dash.set_defaults(func=_cmd_dashboard)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
