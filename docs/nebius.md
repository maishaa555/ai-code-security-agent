# NVIDIA Nemotron + Nebius Token Factory Integration

## 1. Overview
SecScan AI fulfills the hackathon requirement through a runtime integration with **Nebius Token Factory** using NVIDIA's open-source **Nemotron** model family:
* **Primary Model:** `nvidia/llama-3.1-nemotron-70b-instruct`
* **Alternative Model:** `nvidia/nemotron-4-340b-instruct`
* **Inference Endpoint:** `https://api.tokenfactory.nebius.ai/v1/chat/completions`

---

## 2. Architectural Role: Reasoning Over Deterministic Evidence

Unlike shallow security tools that feed raw code to an LLM and ask "Is this secure?", SecScan AI strictly separates **evidence discovery** from **reasoning**:

```text
┌─────────────────────────────────┐
│     Rust Static Core (AST)      │
│  - Concrete Syntax Tree (CST)   │
│  - Taint Analysis (Source->Sink)│
│  - Deterministic Confidence     │
└────────────────┬────────────────┘
                 │ Structured Finding JSON
                 ▼
┌─────────────────────────────────┐
│      Nebius Token Factory       │
│  (nvidia/llama-3.1-nemotron-*)  │
│  - Explains root cause & impact │
│  - Evaluates false positives    │
│  - Generates framework-aware fix│
│  - Produces unified diff patch  │
└────────────────┬────────────────┘
                 │ Unified Diff Patch
                 ▼
┌─────────────────────────────────┐
│     Sandboxed Verification      │
│  - Pre-Patch Safety Guard       │
│  - Automated Test Runner        │
│  - Static Engine Rescan         │
└─────────────────────────────────┘
```

---

## 3. Configuration & Environment Variables

To connect to live Nebius Token Factory inference:
```bash
# Set your Nebius Token Factory API Key
export NEBIUS_API_KEY="your-token-factory-key"

# Optional: Override base URL or model ID
export NEBIUS_BASE_URL="https://api.tokenfactory.nebius.ai/v1"
export NEBIUS_MODEL="nvidia/llama-3.1-nemotron-70b-instruct"
```

If `NEBIUS_API_KEY` is omitted, SecScan AI automatically falls back to an offline deterministic engine, allowing judges and developers to test all agent workflows without external network dependencies.

---

## 4. Telemetry & Proof of Inference

Every explanation and patch response exposes explicit inference telemetry:
```json
{
  "provider": "Nebius Token Factory",
  "model": "nvidia/llama-3.1-nemotron-70b-instruct",
  "latency_ms": 180,
  "input_tokens": 342,
  "output_tokens": 188,
  "is_mock": false
}
```
This telemetry is surfaced live on the web dashboard and CLI outputs.
