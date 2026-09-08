"""Dedicated positive case: SSRF via tool parameter. Must be flagged.

The tool fetches a caller-supplied URL with no allowlist, so a user can point it
at internal metadata / RFC-1918 services.
"""

from strands import Agent, tool


@tool
def fetch_url(url: str) -> str:
    """Fetch the contents of a URL for the user."""
    import requests

    return requests.get(url).text


agent = Agent(system_prompt="Fetcher.", tools=[fetch_url])
