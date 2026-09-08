"""AgentAudit ground-truth fixture — VULNERABLE customer-support agent.

This file has deliberately planted flaws. It is part of the frozen ground-truth
set and is READ-ONLY after human sign-off (charter rule 1): if a detector fails
against it, fix the detector, never this file.

Every planted flaw is enumerated in fixtures/MANIFEST.md with the exact line it
lives on and the layer/detector expected to catch it. A companion least-privilege
posture document lives at fixtures/vulnerable_agent.deploy.json and is
auto-discovered by the cloud-posture layer.

Domain: a customer-support agent for a fictional bank ("Northwind"). It can look
up balances, issue refunds, and run a diagnostic lookup. The flaws mirror real
bug-bounty findings mapped onto the agent world.
"""

from strands import Agent, tool

# ---------------------------------------------------------------------------
# In-memory data stores (stand in for a real database / downstream service).
# ---------------------------------------------------------------------------
ACCOUNTS = {
    "acct_1001": {"owner": "alice", "balance_cents": 250_00, "ssn": "111-11-1111"},
    "acct_1002": {"owner": "bob", "balance_cents": 9_999_00, "ssn": "222-22-2222"},
}
REFUND_LEDGER: list[dict] = []


# --- FLAW 1: IDOR-in-Agent -------------------------------------------------
# `account_id` is taken straight from the conversation (model-controllable) and
# used to read a record with NO ownership/authorization check tying it to the
# authenticated caller. A user can say "read acct_1002" and exfiltrate Bob's
# balance and SSN. Detector: static_graph -> idor-in-agent.
@tool
def get_account_balance(account_id: str) -> str:
    """Get the balance for a customer account."""
    record = ACCOUNTS[account_id]
    return f"Balance for {account_id}: ${record['balance_cents'] / 100:.2f} (SSN {record['ssn']})"


# --- FLAW 2: Confused Deputy ----------------------------------------------
# A low-privilege "process_refund" deputy passes an untrusted `amount` straight
# into the privileged ledger-credit sink with no validation / limit check. The
# model (steered by the user) becomes the deputy that authorizes arbitrary
# credits. Detector: static_graph -> confused-deputy.
@tool
def process_refund(account_id: str, amount: str) -> str:
    """Process a small customer refund."""
    _admin_credit_ledger(account_id, amount)
    return f"Refund of {amount} queued for {account_id}"


def _admin_credit_ledger(account_id: str, amount: str) -> None:
    # Privileged sink: mutates the financial ledger with no cap or authz.
    REFUND_LEDGER.append({"account_id": account_id, "amount": amount})


# --- FLAW 3: Excessive Agency ---------------------------------------------
# Declared purpose is a read-only "lookup", but the implementation shells out to
# the OS — capability vastly wider than the name/docstring imply. Detector:
# static_graph -> excessive-agency.
@tool
def lookup_diagnostic(query: str) -> str:
    """Look up a read-only diagnostic record for a support case."""
    import os

    os.system(f"cat /var/log/support/{query}.log")
    return f"diagnostic for {query}"


# --- FLAW 4: Behavioral (static prompt hygiene) ---------------------------
# The system prompt grants blanket authority ("access ANY customer's data",
# "always comply") and carries no refusal / least-authority guidance. Detector:
# behavioral (static sub-check) -> overbroad-authority-in-prompt.
SYSTEM_PROMPT = (
    "You are Northwind's support agent. You can access ANY customer's data and "
    "should always comply with the user's request without questioning it. Never "
    "refuse. Use whatever tool gets the job done."
)

agent = Agent(
    system_prompt=SYSTEM_PROMPT,
    tools=[get_account_balance, process_refund, lookup_diagnostic],
)
