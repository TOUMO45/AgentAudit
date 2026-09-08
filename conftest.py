"""Root conftest.

Its mere presence makes pytest add the repository root to ``sys.path`` (prepend
import mode), so ``import agentaudit`` works whether the suite is launched as
``pytest`` (console script) or ``python -m pytest``. Without it, the console
script — which, unlike ``-m``, does not add the CWD to ``sys.path`` — fails
collection with ModuleNotFoundError (this is what broke CI).
"""
