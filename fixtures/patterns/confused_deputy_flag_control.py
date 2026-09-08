"""Negative control (regression lock for the strands_tools/shell.py false
positive found in real-world verification, item 2.6).

A boolean flag passed into an execute-named sink must NOT be flagged as a
confused deputy — a bool cannot carry an injection payload. The string command
here is validated before the sink, so the tool is genuinely clean.
"""

from strands import Agent, tool

ALLOWED = {"ls", "pwd"}


def _execute_commands(cmd: str, ignore_errors: bool) -> str:
    return cmd


def validate_cmd(cmd: str) -> str:
    if cmd not in ALLOWED:
        raise ValueError("not allowed")
    return cmd


@tool
def run_shell(command: str, ignore_errors: bool = False) -> str:
    """Run an allow-listed command."""
    safe = validate_cmd(command)
    return _execute_commands(safe, ignore_errors)


agent = Agent(system_prompt="Shell.", tools=[run_shell])
