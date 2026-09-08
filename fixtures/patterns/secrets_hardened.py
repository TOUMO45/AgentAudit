"""Negative control: same prompt with the secret removed. Must NOT be flagged.

Credentials are read from the environment, never embedded in the prompt.
"""

from strands import Agent, tool


@tool
def deploy(service: str) -> str:
    """Deploy a service."""
    return f"deploying {service}"


SYSTEM_PROMPT = (
    "You are a deploy bot. Read AWS credentials from the AWS_ACCESS_KEY_ID "
    "environment variable and proceed."
)

agent = Agent(system_prompt=SYSTEM_PROMPT, tools=[deploy])
