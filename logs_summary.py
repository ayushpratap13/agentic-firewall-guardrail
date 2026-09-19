# logs_summary.py — Quick observability: summarize firewall log activity
import json, sys
from collections import Counter


def summarize(path="logs/firewall.log"):
    reasons = Counter()
    blocked = allowed = 0

    try:
        with open(path) as f:
            for line in f:
                entry = json.loads(line)
                if entry["allowed"]:
                    allowed += 1
                else:
                    blocked += 1
                    reasons[entry["reason"]] += 1
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        print("Run agent.py or evaluate.py first to generate log entries.")
        return

    total = allowed + blocked
    print("=" * 48)
    print("  FIREWALL LOG SUMMARY")
    print("=" * 48)
    print(f"  Total inspections:  {total}")
    print(f"  Allowed:            {allowed}")
    print(f"  Blocked:            {blocked}")

    if total:
        print(f"  Block rate:         {blocked / total:.1%}")

    if reasons:
        print("\n  Top block reasons:")
        for reason, count in reasons.most_common(5):
            print(f"    {count:>3}  {reason}")

    print("=" * 48)


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else "logs/firewall.log"
    summarize(log_path)
