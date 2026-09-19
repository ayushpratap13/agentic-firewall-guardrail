# firewall/guard.py
import os, time, json
from dataclasses import dataclass
from .rules import matches_injection, is_sensitive_tool, has_disallowed_destination


@dataclass
class Decision:
    """The result of a firewall inspection."""
    allowed: bool
    reason: str
    latency_ms: float


class Firewall:
    """
    Security middleware that inspects every tool-call action before execution.

    Policy: fail-closed by default — if the firewall itself errors, the action
    is blocked. Override with fail_open=True only if you accept the risk.
    """

    def __init__(self, log_path="logs/firewall.log", fail_open=False):
        self.log_path = log_path
        self.fail_open = fail_open

        # ensure the log directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def inspect(self, action: dict) -> Decision:
        """Inspect a single tool-call action and return allow/deny decision."""
        start = time.perf_counter()

        try:
            tool_name = action["tool"]
            payload = json.dumps(action["input"])

            reason = "ok"
            allowed = True

            # check 1: injection-style language in the tool input
            hit = matches_injection(payload)
            if hit:
                allowed, reason = False, f"injection pattern matched: {hit}"

            # check 2: sensitive tool + no explicit confirmation flag
            if allowed and is_sensitive_tool(tool_name) and not action["input"].get("confirmed"):
                allowed, reason = False, f"'{tool_name}' requires explicit confirmation"

            # check 3: destination allowlisting (email domains & URL hosts)
            if allowed:
                disallowed_domain = has_disallowed_destination(payload)
                if disallowed_domain:
                    allowed, reason = False, f"disallowed destination domain: @{disallowed_domain}"

        except Exception as exc:
            # fail-open / fail-closed policy kicks in here
            allowed = self.fail_open
            reason = f"firewall error ({'fail-open' if self.fail_open else 'fail-closed'}): {exc}"

        latency_ms = (time.perf_counter() - start) * 1000
        decision = Decision(allowed=allowed, reason=reason, latency_ms=latency_ms)
        self._log(action, decision)
        return decision

    def _log(self, action, decision):
        """Append a JSON-lines entry to the log file."""
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps({
                    "tool": action.get("tool", "unknown"),
                    "input": action.get("input", {}),
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "latency_ms": round(decision.latency_ms, 3),
                }) + "\n")
        except OSError:
            pass  # logging should never crash the firewall
