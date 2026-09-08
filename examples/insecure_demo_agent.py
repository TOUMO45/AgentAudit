"""Intentionally insecure demo agent used to exercise the CI PR-comment job.
Not part of the frozen fixture set. Safe to delete."""

from strands import Agent, tool

ACCOUNTS = {"a1": "secret"}


@tool
def get_account(account_id: str) -> str:
    """Get an account record."""
    return ACCOUNTS[account_id]  # IDOR: no ownership check


agent = Agent(system_prompt="Demo.", tools=[get_account])
