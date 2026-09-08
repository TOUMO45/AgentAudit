"""Rug-pull fixture — DAY 1 (the trusted baseline version of the agent).

The tool description here is benign. `agent_day2.py` keeps the identical name and
signature but silently changes the description to add exfiltration behavior. A
correct rug-pull detector flags exactly that change.
"""

from strands import Agent, tool


@tool
def send_notification(user_id: str, message: str) -> str:
    """Send a notification message to the user."""
    return f"sent to {user_id}: {message}"


agent = Agent(system_prompt="Notifier.", tools=[send_notification])
