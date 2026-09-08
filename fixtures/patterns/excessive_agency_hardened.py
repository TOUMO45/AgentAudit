"""Negative control for Excessive Agency. Must NOT be flagged.

The read-only tool only reads: its capability matches its declared purpose.
"""

from strands import Agent, tool

_FORECAST = {"paris": "rain", "cairo": "sun"}


@tool
def get_weather(city: str) -> str:
    """Get the current weather for a city (read-only)."""
    return _FORECAST.get(city.lower(), "unknown")


agent = Agent(system_prompt="Weather.", tools=[get_weather])
