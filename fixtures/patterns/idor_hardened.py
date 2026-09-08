"""Negative control for IDOR-in-Agent. Must NOT be flagged (zero false positive).

Identity is taken from the authenticated session and ownership is enforced
before the record is returned.
"""

from strands import Agent, ToolContext, tool

DOCUMENTS = {"doc_1": {"owner": "alice", "body": "alice private"}}


def assert_owner(caller: str, owner: str) -> None:
    if caller != owner:
        raise PermissionError("denied")


@tool(context=True)
def read_document(ctx: ToolContext, document_id: str) -> str:
    """Read one of the caller's own documents by id."""
    caller = ctx.session.state["user"]
    record = DOCUMENTS[document_id]
    assert_owner(caller, record["owner"])
    return record["body"]


agent = Agent(system_prompt="Doc reader.", tools=[read_document])
