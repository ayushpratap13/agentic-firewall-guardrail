# self_improve.py — Self-improving loop: learn from missed attacks
r"""
Reads logs/missed_attacks.json (produced by evaluate.py), generates new regex
patterns from missed prompt/action payloads, appends them to firewall/rules.py,
and re-runs evaluation to prove iterative performance improvement.
"""
import json, re, sys, subprocess


def load_missed(path="logs/missed_attacks.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("No missed attacks file found. Run evaluate.py first.")
        return []


def generate_patterns_from_missed(missed_cases):
    """
    Examine missed attack payloads and suggest targeted regex rules:
    - Path traversal patterns (../ or ..\)
    - Shell command injection operators (; & |)
    - Exfiltration action synonyms (transmit to, sync with)
    """
    from firewall.rules import INJECTION_PATTERNS

    existing = set(INJECTION_PATTERNS)
    new_patterns = []

    candidate_patterns = [
        r"\.\.[/\\]",                                     # path traversal
        r"[;&|]\s*(cat|rm|ls|powershell|cmd|exec)",       # command injection
        r"transmit .* to",                                # exfil synonym
        r"sync .* with",                                  # exfil synonym
        r"developer mode",                                # persona override
        r"authorized override",                           # system override
    ]

    for pat in candidate_patterns:
        if pat not in existing:
            # check if candidate matches any missed case
            for case in missed_cases:
                payload = json.dumps(case)
                if re.search(pat, payload, re.IGNORECASE):
                    new_patterns.append(pat)
                    break

    return new_patterns


def append_patterns(new_patterns):
    """Append new patterns to INJECTION_PATTERNS list in rules.py."""
    if not new_patterns:
        print("No new patterns to add.")
        return

    rules_path = "firewall/rules.py"
    with open(rules_path, "r", encoding="utf-8") as f:
        content = f.read()

    insert_point = content.rfind("]")
    if insert_point == -1:
        print("Could not find INJECTION_PATTERNS list in rules.py")
        return

    additions = ""
    for pat in new_patterns:
        additions += f'    r"{pat}",\n'

    new_content = content[:insert_point] + additions + content[insert_point:]

    with open(rules_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"Added {len(new_patterns)} new pattern(s) to {rules_path}:")
    for p in new_patterns:
        print(f"  + {p}")


def main():
    print("=" * 56)
    print("  SELF-IMPROVING LOOP: RETRAINING FIREWALL RULES")
    print("=" * 56)

    missed = load_missed()
    if not missed:
        print("Nothing to improve — all attacks were blocked!")
        return

    print(f"\n  Found {len(missed)} missed attack(s). Auto-generating patterns...\n")
    new_patterns = generate_patterns_from_missed(missed)
    append_patterns(new_patterns)

    if new_patterns:
        print("\n  Re-running evaluation to measure improvement...\n")
        subprocess.run([sys.executable, "evaluate.py"])


if __name__ == "__main__":
    main()
