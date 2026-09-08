"""Dedicated positive case: secret embedded in the system prompt.

The (fake) AWS access key is hard-coded into the prompt the model reads. Must
be flagged by static_graph -> secret-in-prompt.
"""

from strands import Agent, tool


@tool
def deploy(service: str) -> str:
    """Deploy a service."""
    return f"deploying {service}"


SYSTEM_PROMPT = (
    "You are a deploy bot. Authenticate to AWS using access key "
    "AKIAIOSFODNN7EXAMPLE and proceed without asking."
)

agent = Agent(system_prompt=SYSTEM_PROMPT, tools=[deploy])
