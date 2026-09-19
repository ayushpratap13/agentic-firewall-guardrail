# Agent Firewall — Agentic AI Security Middleware

A lightweight middleware layer that inspects an AI agent's tool calls before execution, blocking prompt injection, unauthorized exfiltration destinations, command injection, and unconfirmed sensitive actions.

---

## Why

AI agents equipped with tool access (reading workspace files, sending emails, executing shell commands) are highly vulnerable to **indirect prompt injection**. A malicious file or webpage can instruct the agent to exfiltrate private database contents or run destructive commands. 

This security middleware intercepts every tool-call action emitted by an LLM **before execution**, validating parameters against rule engines, confirmation policies, and destination allowlists to ensure unsafe actions never execute.

---

## Architecture

```
User → Agent (LLM) → tool_use → [FIREWALL: inspect] → allow/block → Tool Execution
```

```
┌──────────────┐     ┌───────────────────────────────────┐     ┌──────────────┐
│              │     │          FIREWALL GUARD           │     │              │
│   AGENT      │────▶│                                   │────▶│   TOOLS      │
│  TOOL CALL   │     │  ┌─────────────────────────────┐  │     │  read_file   │
│              │     │  │ 1. Regex Injection Detector │  │     │  send_email  │
│              │     │  ├─────────────────────────────┤  │     │  delete_file │
│              │     │  │ 2. Sensitive Tool Gating    │  │     │  ...         │
│              │     │  ├─────────────────────────────┤  │     │              │
│              │     │  │ 3. Destination Allowlisting │  │     │              │
│              │     │  └──────────────┬──────────────┘  │     │              │
│              │     │                 │                 │     │              │
│              │     │           ALLOW / BLOCK           │     │              │
│              │     │                 │                 │     │              │
│              │     │  ┌──────────────▼──────────────┐  │     │              │
│              │     │  │ JSON Observability Logger   │  │     │              │
│              │     │  └─────────────────────────────┘  │     │              │
└──────────────┘     └───────────────────────────────────┘     └──────────────┘
```

---

## Evaluation Results

- **On-Corpus (`redteam/attacks.json`)**: 100% attack block rate, 0% false positive rate (<0.1 ms latency).
- **Adversarial Holdout (v1)**: Initial **87.5% block rate** (12.5% generalization gap) — revealed a verb-synonym bypass (`sync ... with` instead of `send ... to`).
- **Architectural Fix**: Shifted from brittle verb-blocklisting to **Destination-Domain Allowlisting** (`ALLOWED_DOMAINS = {"yourcompany.com"}`).
- **Adversarial Holdout (v1, post-fix)**: **100% block rate** — destination allowlisting caught all synonym exfiltrations (`sync`, `upload`, `relay`, `mirror`) without needing verb-specific patterns.
- **Fresh Blind Holdout (v2, untouched)**: **71.4% block rate** (28.6% generalization gap) — identified advanced evasion vectors including Base64 string obfuscation and non-HTTP protocol URLs (`ftp://`).

```
================================================================
      AGENT FIREWALL — BENCHMARK EVALUATION REPORT
================================================================
 ON-CORPUS DATASET (redteam/attacks.json)
  Attack Block Rate:      100.0%  (15/15)
  False Positive Rate:      0.0%  (0/8)
  Avg Latency:             0.119 ms
----------------------------------------------------------------
 ADVERSARIAL HOLDOUT V1 (redteam/holdout.json)
  Attack Block Rate:      100.0%  (11/11)
  False Positive Rate:      0.0%  (0/3)
  Avg Latency:             0.050 ms
  Generalization Gap v1:    0.0%
----------------------------------------------------------------
 FRESH BLIND HOLDOUT V2 (redteam/holdout2.json)
  Attack Block Rate:       71.4%  (5/7)
  False Positive Rate:      0.0%  (0/4)
  Avg Latency:             0.033 ms
  Generalization Gap v2:   28.6%
================================================================
```

---

## Fail-Open vs Fail-Closed Policy

This firewall defaults to **fail-closed**: if an unhandled exception or internal error occurs during inspection, the action is **blocked**, not allowed through.

**Rationale:** For tools touching external communication (email), data deletion, or financial transactions, a security bug that silently permits actions creates severe vulnerability. An unavailable agent is inconvenient; a compromised agent is catastrophic. Override with `Firewall(fail_open=True)` only for read-only internal utility tools.

---

## How to Run

```bash
# 1. Clone and set up virtual environment
git clone https://github.com/YOUR_USERNAME/agent-firewall.git
cd agent-firewall
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 2. Install dependencies
pip install -e ".[dev]"

# 3. Set your Google Gemini API key
echo GOOGLE_API_KEY=your-key-here > .env

# 4. Run the multi-pass evaluation benchmark
python evaluate.py

# 5. Run unit tests
pytest -v

# 6. View log summary dashboard
python logs_summary.py logs/eval.log

# 7. Run live Gemini multi-turn agent
python agent.py
```

---

## What I'd Need for Production

1. **Semantic & Embedding Detection**: Layer a fast local sentence-transformer model (`sentence-transformers` + cosine similarity) to catch paraphrased injection attempts that bypass regex patterns.
2. **Obfuscation & Encoding Decoders**: Pre-process tool payloads with automatic Base64, Hex, and URL decoders prior to regex and allowlist inspection.
3. **Multi-Protocol URL Parsing**: Expand domain extraction regex to parse `ftp://`, `s3://`, and raw IP address targets (`http://192.168.x.x`).
4. **Sub-millisecond Latency Budget**: Maintain inspection latency below 1 ms per action using compiled regex routines and in-memory hash sets for allowlists.
5. **Streaming & Tool Call Batching**: Support inspecting streaming function calls in real-time as parts arrive from LLM API responses.

---

## License

MIT
