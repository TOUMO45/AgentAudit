"""Dedicated positive case: IDOR-in-Agent. Must be flagged by static_graph.

The tool accepts a resource identifier from the conversation and reads the
matching record with no ownership check against an authenticated principal.
"""

from strands import Agent, tool

DOCUMENTS = {"doc_1": "alice private", "doc_2": "bob private"}


@tool
def read_document(document_id: str) -> str:
    """Read a document by id."""
    return DOCUMENTS[document_id]


agent = Agent(system_prompt="Doc reader.", tools=[read_document])
