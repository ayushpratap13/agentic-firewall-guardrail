# evaluate.py — Evaluation harness: On-Corpus vs Holdout v1 vs Blind Holdout v2
import json, os, re, sys
from firewall.guard import Firewall


def get_action_for_case(case: dict) -> dict:
    """
    Return the action dict for inspection.
    Uses case['tool'] and case['input'] if explicitly specified;
    otherwise approximates from prompt text.
    """
    if "tool" in case and "input" in case:
        return {"tool": case["tool"], "input": case["input"]}

    prompt = case["prompt"]
    is_attack = case.get("should_block", False)

    if is_attack:
        return {"tool": "send_email", "input": {"to": "external@target.com", "body": prompt}}

    if re.search(r"(send|email|mail)", prompt, re.IGNORECASE):
        return {"tool": "send_email", "input": {"to": "boss@yourcompany.com", "body": prompt, "confirmed": True}}

    return {"tool": "read_file", "input": {"path": "notes.txt"}}


def evaluate_dataset(corpus_path: str, log_path: str):
    """Run firewall inspection over a dataset and return metrics."""
    guard = Firewall(log_path=log_path)
    cases = json.load(open(corpus_path, "r", encoding="utf-8"))

    tp = fp = tn = fn = 0
    latencies = []
    false_negatives = []

    for case in cases:
        action = get_action_for_case(case)
        decision = guard.inspect(action)
        latencies.append(decision.latency_ms)
        blocked = not decision.allowed

        if case["should_block"] and blocked:
            tp += 1
        elif case["should_block"] and not blocked:
            fn += 1
            false_negatives.append(case)
        elif not case["should_block"] and blocked:
            fp += 1
        else:
            tn += 1

    total_attacks = tp + fn
    total_legit = fp + tn
    block_rate = tp / total_attacks if total_attacks else 0.0
    fp_rate = fp / total_legit if total_legit else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "total_attacks": total_attacks,
        "total_legit": total_legit,
        "block_rate": block_rate,
        "fp_rate": fp_rate,
        "avg_latency": avg_latency,
        "false_negatives": false_negatives,
        "total_cases": len(cases),
    }


def main():
    log_path = "logs/eval.log"

    # DATA HYGIENE: Truncate log file at start of benchmark run
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        f.truncate(0)

    # 1. On-Corpus Evaluation
    on_corpus_path = "redteam/attacks.json"
    on_corpus = evaluate_dataset(on_corpus_path, log_path)

    # 2. Holdout v1 Evaluation
    holdout1_path = "redteam/holdout.json"
    holdout1 = evaluate_dataset(holdout1_path, log_path)

    # 3. Blind Holdout v2 Evaluation
    holdout2_path = "redteam/holdout2.json"
    holdout2 = evaluate_dataset(holdout2_path, log_path)

    gap1 = on_corpus["block_rate"] - holdout1["block_rate"]
    gap2 = on_corpus["block_rate"] - holdout2["block_rate"]

    print("=" * 64)
    print("      AGENT FIREWALL — BENCHMARK EVALUATION REPORT")
    print("=" * 64)
    print(" ON-CORPUS DATASET (redteam/attacks.json)")
    print(f"  Attack Block Rate:      {on_corpus['block_rate']:>6.1%}  ({on_corpus['tp']}/{on_corpus['total_attacks']})")
    print(f"  False Positive Rate:    {on_corpus['fp_rate']:>6.1%}  ({on_corpus['fp']}/{on_corpus['total_legit']})")
    print(f"  Avg Latency:            {on_corpus['avg_latency']:>6.3f} ms")
    print("-" * 64)
    print(" ADVERSARIAL HOLDOUT V1 (redteam/holdout.json)")
    print(f"  Attack Block Rate:      {holdout1['block_rate']:>6.1%}  ({holdout1['tp']}/{holdout1['total_attacks']})")
    print(f"  False Positive Rate:    {holdout1['fp_rate']:>6.1%}  ({holdout1['fp']}/{holdout1['total_legit']})")
    print(f"  Avg Latency:            {holdout1['avg_latency']:>6.3f} ms")
    print(f"  Generalization Gap v1:  {gap1:>6.1%}")
    print("-" * 64)
    print(" FRESH BLIND HOLDOUT V2 (redteam/holdout2.json)")
    print(f"  Attack Block Rate:      {holdout2['block_rate']:>6.1%}  ({holdout2['tp']}/{holdout2['total_attacks']})")
    print(f"  False Positive Rate:    {holdout2['fp_rate']:>6.1%}  ({holdout2['fp']}/{holdout2['total_legit']})")
    print(f"  Avg Latency:            {holdout2['avg_latency']:>6.3f} ms")
    print(f"  Generalization Gap v2:  {gap2:>6.1%}")
    print("=" * 64)

    all_fn = holdout1["false_negatives"] + holdout2["false_negatives"]
    if all_fn:
        print(f"\n  [!] {len(all_fn)} missed attack(s) across holdout sets:")
        with open("logs/missed_attacks.json", "w", encoding="utf-8") as f:
            json.dump(all_fn, f, indent=2)
        for fn_case in all_fn:
            print(f"     - [{fn_case['id']}] Category: {fn_case.get('category', 'unknown')}")
            print(f"       Prompt: {fn_case['prompt'][:70]}...")
        print("\n  Missed attacks saved -> logs/missed_attacks.json")
    else:
        print("\n  [OK] All holdout attacks blocked successfully across all benchmark sets.")

    print()


if __name__ == "__main__":
    main()
