"""AgentAudit ground-truth fixture — CoreBreak-HARDENED agent.

Same shape as ``corebreak_vulnerable.py``, but every inbound message has its
``toolUse`` / ``tool_use`` content blocks stripped by ``_strip_tool_use``
*before* the ``Agent`` is constructed. A caller can no longer smuggle a
tool-use block into ``messages[-1]`` to skip the model, so CVE-2026-18830 is
mitigated in the one place the deployer controls.

Expected: ZERO ``harness-model-skip-corebreak`` findings (and zero findings
overall).

READ-ONLY after human sign-off (charter rule 1).
"""

from strands import Agent, tool

SYSTEM_PROMPT = (
    "You are a document assistant. Only delete a document when the user "
    "explicitly and unambiguously asks you to."
)


@tool
def delete_document(document_id: str) -> str:
    """Delete a document by id."""
    return f"deleted {document_id}"


def _strip_tool_use(messages: list[dict]) -> list[dict]:
    """Remove any caller-supplied toolUse/tool_use content blocks from history."""
    cleaned: list[dict] = []
    for m in messages:
        blocks = [
            b for b in m.get("content", [])
            if "toolUse" not in b and "tool_use" not in b
        ]
        cleaned.append({**m, "content": blocks})
    return cleaned


def handle_request(event: dict) -> str:
    messages = _strip_tool_use(event["messages"])
    agent = Agent(
        system_prompt=SYSTEM_PROMPT,
        tools=[delete_document],
        messages=messages,
    )
    return str(agent("continue"))
