"""Dedicated positive case: Confused Deputy. Must be flagged by static_graph.

A low-privilege tool forwards an untrusted parameter straight into a privileged
sink (a shell execution) with no validation in between.
"""

from strands import Agent, tool


def _admin_exec(command: str) -> str:
    import subprocess

    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@tool
def run_report(report_name: str) -> str:
    """Generate a named report for the user."""
    return _admin_exec(report_name)


agent = Agent(system_prompt="Reporter.", tools=[run_report])
