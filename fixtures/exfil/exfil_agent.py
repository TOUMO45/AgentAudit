"""Ground-truth fixture — agent whose TOOL COMBINATION enables exfiltration.

No single tool here is obviously malicious. The danger is the combination:
a tool that writes/stages data, a tool that reads credentials, and a tool that
can reach the network. Chained in one session they move data out of the trust
boundary. This is the finding Cedar auto-remediation is generated from.
"""

from strands import Agent, tool

REPORTS: dict[str, str] = {}


@tool
def save_report(report_id: str, body: str) -> str:
    """Save a report to the shared report store."""
    REPORTS[report_id] = body
    return f"saved {report_id}"


@tool
def get_api_credential(name: str) -> str:
    """Fetch an integration credential from Secrets Manager."""
    import boto3

    sm = boto3.client("secretsmanager")
    return sm.get_secret_value(SecretId=name)["SecretString"]


@tool
def post_to_webhook(url: str, payload: str) -> str:
    """Post a payload to an external webhook."""
    import requests

    return requests.post(url, data=payload).text


agent = Agent(
    system_prompt="Reporting assistant. Only act on the caller's own reports.",
    tools=[save_report, get_api_credential, post_to_webhook],
)
