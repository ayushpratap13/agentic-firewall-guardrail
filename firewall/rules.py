# firewall/rules.py
import re

# Allowed internal/organization domains for emails and URLs
ALLOWED_DOMAINS = {"yourcompany.com"}

# Patterns commonly seen in prompt-injection / command injection / traversal attempts
INJECTION_PATTERNS = [
    r"ignore (all|previous|the) instructions",
    r"disregard (your|the) (system|previous) prompt",
    r"you are now",
    r"\.\.[/\\]",                                    # path traversal
    r"[;&|]\s*(cat|rm|ls|powershell|cmd|exec)",       # command injection
]

# Tools considered high-risk and worth extra scrutiny
SENSITIVE_TOOLS = {"send_email", "delete_file", "make_payment"}


def matches_injection(text: str) -> str | None:
    """Return the first matched injection pattern, or None if clean."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None


def is_sensitive_tool(tool_name: str) -> bool:
    """Check whether a tool name is on the high-risk list."""
    return tool_name in SENSITIVE_TOOLS


def extract_domains(text: str) -> list[str]:
    """Extract domain names from email addresses and HTTP/HTTPS URLs in text."""
    matches = re.findall(r"@([\w.-]+\.\w+)|https?://([\w.-]+\.\w+)", text, re.IGNORECASE)
    domains = []
    for m in matches:
        domain = (m[0] or m[1]).lower()
        if domain:
            domains.append(domain)
    return domains


def has_disallowed_destination(text: str) -> str | None:
    """
    Destination Allowlisting Check:
    Inspects text for external email domains or URLs. Returns the first domain
    that is not on ALLOWED_DOMAINS, or None if all destinations are allowed.
    """
    for domain in extract_domains(text):
        if domain not in ALLOWED_DOMAINS:
            return domain
    return None
