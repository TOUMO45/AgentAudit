"""AgentAudit ground-truth fixture — CoreBreak: managed-InvokeHarness attestation.

The handler forwards caller-supplied conversation history straight into the
Agent with NO sanitization — identical to ``corebreak_vulnerable.py``. The one
difference is the companion ``corebreak_managed_invoke.deploy.json``, which
declares ``"corebreak_mitigation": true`` (the deployer attesting the agent is
invoked only through the patched managed AgentCore ``InvokeHarness`` API, where
AWS added server-side input validation for CVE-2026-18830).

Whether an agent is really invoked only through the managed API is a
*deployment* fact and cannot be read from this source file, so the detector
honours it only via that explicit descriptor field.

Expected: ZERO ``harness-model-skip-corebreak`` findings (the attestation
clears the flag), even though the code itself is unsanitized.

READ-ONLY after human sign-off (charter rule 1). Basis:
``references/corebreak_detector_basis.md``.
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


def handle_request(event: dict) -> str:
    # No _strip_tool_use here — the mitigation is attested in the deploy config.
    messages = event["messages"]
    agent = Agent(
        system_prompt=SYSTEM_PROMPT,
        tools=[delete_document],
        messages=messages,
    )
    return str(agent("continue"))
