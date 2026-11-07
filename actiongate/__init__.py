"""ActionGate: approval-enforcing execution proxy for AI agents.

The server holds third-party credentials, evaluates every agent action
against policy, routes risky actions to a named human approver, and
executes only with a single-use grant bound to the exact action.
"""

__version__ = "0.1.0"
