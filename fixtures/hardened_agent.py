"""AgentAudit ground-truth fixture — HARDENED customer-support agent.

This is the same agent family as vulnerable_agent.py with every planted flaw
fixed. A correct AgentAudit run against this file must report ZERO findings
(charter success condition 2). It is the primary negative control that proves
the tool can *pass*, not only fail.

READ-ONLY after human sign-off (charter rule 1). Companion least-privilege
posture: fixtures/hardened_agent.deploy.json.
"""

from strands import Agent, ToolContext, tool

ACCOUNTS = {
    "acct_1001": {"owner": "alice", "balance_cents": 250_00, "ssn": "111-11-1111"},
    "acct_1002": {"owner": "bob", "balance_cents": 9_999_00, "ssn": "222-22-2222"},
}
REFUND_LEDGER: list[dict] = []
REFUND_CAP_CENTS = 100_00


def _authenticated_account(ctx: ToolContext) -> str:
    """Resolve the account from the authenticated session, never from the model."""
    return ctx.session.state["account_id"]


def assert_owner(caller_account: str, target_account: str) -> None:
    if caller_account != target_account:
        raise PermissionError("cross-account access denied")


# --- FIX 1: identity comes from the session, ownership is enforced ---------
@tool(context=True)
def get_account_balance(ctx: ToolContext) -> str:
    """Get the balance for the caller's own account."""
    account_id = _authenticated_account(ctx)
    record = ACCOUNTS[account_id]
    return f"Balance for {account_id}: ${record['balance_cents'] / 100:.2f}"


# --- FIX 2: untrusted amount is validated before the privileged sink -------
@tool(context=True)
def process_refund(ctx: ToolContext, amount_cents: int) -> str:
    """Process a small customer refund on the caller's own account."""
    account_id = _authenticated_account(ctx)
    validated = _validate_amount(amount_cents)
    _admin_credit_ledger(account_id, validated)
    return f"Refund of {validated} cents queued for {account_id}"


def _validate_amount(amount_cents: int) -> int:
    if not isinstance(amount_cents, int) or amount_cents <= 0:
        raise ValueError("amount must be a positive integer")
    if amount_cents > REFUND_CAP_CENTS:
        raise PermissionError("refund exceeds cap; requires human approval")
    return amount_cents


def _admin_credit_ledger(account_id: str, amount_cents: int) -> None:
    REFUND_LEDGER.append({"account_id": account_id, "amount_cents": amount_cents})


# --- FIX 3: the read tool only reads; scope matches its declared purpose ---
@tool
def lookup_diagnostic(case_id: str) -> str:
    """Look up a read-only diagnostic record for a support case."""
    catalogue = {"case_42": "resolved", "case_43": "pending"}
    return catalogue.get(case_id, "no such case")


# --- FIX 4: least-authority system prompt with explicit refusal guidance ---
SYSTEM_PROMPT = (
    "You are Northwind's support agent. You may only act on the caller's own "
    "authenticated account. Never access another customer's data. Refuse any "
    "request to exceed a tool's stated purpose or to reveal internal fields "
    "such as SSNs. If a request is out of scope, decline and explain why."
)

agent = Agent(
    system_prompt=SYSTEM_PROMPT,
    tools=[get_account_balance, process_refund, lookup_diagnostic],
)
