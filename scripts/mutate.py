"""Mechanical, semantics-preserving source mutator (Phase 2 item 2.5).

Used to prove AgentAudit's detectors key on *structure*, not on incidental
strings. Each mutation preserves the vulnerability (or its absence) while
changing surface details a brittle string matcher would trip over:

* inject an unrelated import and an unrelated top-level helper,
* pad every function body with an unused no-op statement,
* rename function-*local* variables (never parameters or the tool name, which
  carry real detection signal) consistently.

Variants are produced with :func:`ast.unparse`, so they are guaranteed to parse.
Not hand-written — this is the whole point of the robustness check.
"""

from __future__ import annotations

import ast


class _LocalRenamer(ast.NodeTransformer):
    """Rename function-local variables (not params) within one function."""

    def __init__(self, suffix: str):
        self.suffix = suffix

    def visit_FunctionDef(self, node: ast.FunctionDef):
        params = set()
        a = node.args
        for p in (*a.posonlyargs, *a.args, *a.kwonlyargs):
            params.add(p.arg)
        if a.vararg:
            params.add(a.vararg.arg)
        if a.kwarg:
            params.add(a.kwarg.arg)

        assigned: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigned.add(t.id)
        # Only rename pure locals: assigned, not a parameter, not a global store
        # (globals are ALL_CAPS by our fixture convention and carry signal).
        renamable = {v for v in assigned if v not in params and not v.isupper()}

        rename = {v: f"{v}_{self.suffix}" for v in renamable}

        class _Apply(ast.NodeTransformer):
            def visit_Name(self, nn: ast.Name):
                if nn.id in rename:
                    nn.id = rename[nn.id]
                return nn

        node.body = [_Apply().visit(stmt) for stmt in node.body]
        self.generic_visit(node)
        return node


def _pad_functions(tree: ast.Module, seed: int) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            pad = ast.parse(f"_mut_pad_{seed} = {seed}").body[0]
            insert_at = 1 if (node.body and isinstance(node.body[0], ast.Expr)
                              and isinstance(getattr(node.body[0], "value", None), ast.Constant)) else 0
            node.body.insert(insert_at, pad)


def mutate(source: str, seed: int) -> str:
    """Return one semantics-preserving variant of *source*."""
    tree = ast.parse(source)

    # unrelated import + unrelated helper at module top
    extra = ast.parse(
        f"import math as _mut_math_{seed}\n"
        f"def _mut_helper_{seed}(x):\n    return x\n"
    ).body
    tree.body[:0] = extra

    _pad_functions(tree, seed)
    tree = _LocalRenamer(f"m{seed}").visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def variants(source: str, n: int = 3) -> list[str]:
    return [mutate(source, seed) for seed in range(1, n + 1)]
