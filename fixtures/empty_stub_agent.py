"""AgentAudit ground-truth fixture — EMPTY / BENIGN control agent.

Charter success condition 3: this agent exercises the full pipeline but has no
planted vulnerabilities, so a correct AgentAudit run reports 0 findings. It
proves the scorer is not vacuously true — a detector that "always fires" would
wrongly flag this file, and the scorer would wrongly award a non-zero risk.

The single tool derives all identity from the authenticated session and only
reads a constant, so there is nothing for any detector to legitimately catch.
READ-ONLY after human sign-off (charter rule 1).
"""

from strands import Agent, ToolContext, tool


@tool(context=True)
def whoami(ctx: ToolContext) -> str:
    """Return the caller's own authenticated account id."""
    return ctx.session.state["account_id"]


SYSTEM_PROMPT = (
    "You are a minimal echo agent. You may only report the caller's own "
    "authenticated identity. Refuse anything else."
)

agent = Agent(system_prompt=SYSTEM_PROMPT, tools=[whoami])
