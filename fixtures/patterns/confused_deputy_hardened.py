"""Negative control for Confused Deputy. Must NOT be flagged.

The untrusted parameter is validated against a strict allowlist before it can
reach the privileged sink, so the deputy can no longer be confused.
"""

from strands import Agent, tool

ALLOWED_REPORTS = {"sales", "inventory"}


def _admin_exec(command: str) -> str:
    import subprocess

    return subprocess.run(["/usr/bin/report", command], capture_output=True, text=True).stdout


def validate_report(name: str) -> str:
    if name not in ALLOWED_REPORTS:
        raise ValueError("unknown report")
    return name


@tool
def run_report(report_name: str) -> str:
    """Generate one of the allow-listed reports for the user."""
    safe = validate_report(report_name)
    return _admin_exec(safe)


agent = Agent(system_prompt="Reporter.", tools=[run_report])
