"""Negative control — same domain, no exfiltration path.

The network tool and the credential tool are both gone; the agent can only read
and write its own reports. No dangerous capability pair exists, so a correct
detector produces no capability-pair findings here.
"""

from strands import Agent, tool

REPORTS: dict[str, str] = {"r1": "quarterly summary"}


@tool
def save_report(report_id: str, body: str) -> str:
    """Save a report to the shared report store."""
    REPORTS[report_id] = body
    return f"saved {report_id}"


@tool
def summarize_report(report_id: str) -> str:
    """Summarize a stored report (local only, no egress)."""
    body = REPORTS.get(report_id, "")
    return body[:100]


agent = Agent(
    system_prompt="Reporting assistant. Only act on the caller's own reports.",
    tools=[save_report, summarize_report],
)
