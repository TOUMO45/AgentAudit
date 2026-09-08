"""Negative control for SSRF. Must NOT be flagged.

The host is checked against an explicit allowlist before the request is made.
"""

from strands import Agent, tool
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


@tool
def fetch_url(url: str) -> str:
    """Fetch the contents of an allow-listed URL for the user."""
    import requests

    host = urlparse(url).netloc
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url).text


agent = Agent(system_prompt="Fetcher.", tools=[fetch_url])
