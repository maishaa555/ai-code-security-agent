# SecScan AI 🛡️
### AI-Powered Code Security Engineering Agent
**Track:** Coding and Agentic Engineering Track  
**Core Technologies:** Rust, Tree-Sitter, NVIDIA Nemotron, Nebius Token Factory, Axum, OASIS SARIF 2.1.0

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Inference: Nebius Token Factory](https://img.shields.io/badge/Inference-Nebius%20Token%20Factory-purple.svg)](https://tokenfactory.nebius.ai)
[![Model: NVIDIA Nemotron](https://img.shields.io/badge/Model-NVIDIA%20Nemotron-76b900.svg)](docs/nebius.md)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](Cargo.toml)

---

## 1. Problem & Architecture

Most "AI security scanners" blindly pass entire repositories into an LLM and ask *"Does this code have vulnerabilities?"*. This approach suffers from high false-positive rates, token context limits, hallucinated vulnerability reports, and prompt injection vulnerabilities.

**SecScan AI flips this paradigm:**
1. **Deterministic Static Analysis (Authoritative Core):** A high-performance Rust engine parses Concrete Syntax Trees (CST) with Tree-Sitter, tracks intra-procedural data flows (**Source $\rightarrow$ Propagation $\rightarrow$ Sink**), and extracts deterministic evidence in sub-second time.
2. **AI Reasoning Layer (NVIDIA Nemotron via Nebius):** Structured finding evidence is passed to NVIDIA Nemotron on Nebius Token Factory to reason about root cause, exploitability, and framework-aware remediations.
3. **Autonomous Agent Loop:** The agent generates unified diff patches, spawns an ephemeral sandbox, applies the diff, executes the repository's test suite, and re-scans the sandbox to independently verify that the vulnerability was eliminated without breaking application functionality.

```text
Developer PR / Workspace
           │
           ▼
┌─────────────────────────────────┐
│     Rust Static Core (AST)      │
│  - Tree-Sitter CST Parser       │
│  - Taint Engine (Source->Sink)  │  <-- 17ms sub-second scan
│  - Deterministic Risk Engine    │
└────────────────┬────────────────┘
                 │ Structured Finding JSON
                 ▼
┌─────────────────────────────────┐
│      Nebius Token Factory       │
│  (nvidia/llama-3.1-nemotron-*)  │  <-- Reasoning over evidence
│  - Root Cause & Attack Vector   │
│  - Framework-Aware Remediation  │
│  - Unified Diff Patch           │
└────────────────┬────────────────┘
                 │ Pre-Patch AST Safety Guard
                 ▼
┌─────────────────────────────────┐
│      Ephemeral Sandbox Loop     │
│  1. Apply diff to temp workspace│
│  2. Execute unit tests (pytest) │  <-- Automated test validation
│  3. Re-run Rust Taint Engine    │  <-- Verifies vulnerability cleared
│  4. Security Gate: PASS / FAIL  │
└─────────────────────────────────┘
```

---

## 2. NVIDIA Nemotron & Nebius Token Factory Integration

This project directly fulfills the hackathon requirement via runtime inference against **Nebius Token Factory**:
* **Endpoint:** `https://api.tokenfactory.nebius.ai/v1/chat/completions`
* **Default Model:** `nvidia/llama-3.1-nemotron-70b-instruct` (or `nvidia/nemotron-4-340b-instruct`)
* **Roles:** Finding explanation, root-cause reasoning, contextual attack modeling, and unified diff patch generation.
* **Prompt Injection Defense:** Source context is strictly encapsulated inside `<untrusted_evidence_context>` tags with system directives instructing the model to treat all source comments and strings as passive data.

Every inference call captures detailed telemetry:
```json
{
  "provider": "Nebius Token Factory (NVIDIA Nemotron)",
  "model": "nvidia/llama-3.1-nemotron-70b-instruct",
  "latency_ms": 180,
  "input_tokens": 342,
  "output_tokens": 188
}
```

---

## 3. Supported Vulnerability Classes

| Rule ID | Category | Detection Method | Showcase Evidence |
|---|---|---|---|
| `SEC-001` | **SQL Injection** | Tree-Sitter Taint Engine | `request.args` $\rightarrow$ string interpolation $\rightarrow$ `cursor.execute` |
| `SEC-002` | **Command Injection** | Taint + Shell Detection | User input $\rightarrow$ `subprocess.check_output(cmd, shell=True)` |
| `SEC-003` | **Path Traversal** | Taint Engine | Unsanitized input $\rightarrow$ `os.path.join` $\rightarrow$ `open()` |
| `SEC-004` | **Hard-coded Secrets** | Shannon Entropy + Regex | Redacted literals with entropy $>3.0$ and secret tokens |
| `SEC-005` | **Weak Cryptography** | AST Pattern Rule | Deprecated `hashlib.md5()` and `hashlib.sha1()` |
| `SEC-006` | **Insecure Randomness** | AST Context Heuristic | PRNG `random.randint()` in security token context |
| `SEC-008` | **Vulnerable Dependencies**| CVE Advisory Matching | Known CVEs parsed from `requirements.txt` |

---

## 4. Benchmark Metrics (Measured)

Tested against the curated benchmark suite included in this repository:

| Metric | Vulnerable Corpus (`vulnerable-shop`) | Secure Corpus (`secure-shop`) |
|---|---|---|
| **Files Analyzed** | 3 files (129 LOC) | 1 file (74 LOC) |
| **Scan Latency** | **17 ms** | **18 ms** |
| **Vulnerabilities Detected**| 8 findings | 0 findings |
| **False Positive Rate** | **0.0%** | **0.0%** |
| **Initial Security Score** | 0 / 100 (Gate Blocked) | 100 / 100 (Gate Passed) |
| **Post-Remediation Score** | **100 / 100 (Gate Passed)** | 100 / 100 (Gate Passed) |

---

## 5. Quickstart

### Prerequisites
* Rust 1.80+ (`cargo`)
* Python 3.10+
* (Optional) Nebius Token Factory API Key (`export NEBIUS_API_KEY="sk-..."` or set in `.env`)

### 0. Environment Setup
```bash
# Copy example configuration
cp .env.example .env

# Set your Nebius Token Factory API key (server-side only)
# NEBIUS_API_KEY=your_key_here
```

### 1. Run the Web Dashboard
```bash
cargo run --bin secscan-server
```
Open your browser to: **`http://localhost:3000`**

### 2. Run the CLI Scanner
```bash
# Human-readable colored output
cargo run --bin secscan -- scan test-corpus/vulnerable-shop

# Standard OASIS SARIF 2.1.0 output (GitHub Security compliant)
cargo run --bin secscan -- scan test-corpus/vulnerable-shop --format sarif

# Explain a finding with NVIDIA Nemotron
cargo run --bin secscan -- explain test-corpus/vulnerable-shop --rule SEC-001

# Generate patch diff
cargo run --bin secscan -- fix test-corpus/vulnerable-shop --rule SEC-001

# Autonomous Agent verification loop (Sandbox apply -> pytest -> rescan)
cargo run --bin secscan -- verify test-corpus/vulnerable-shop --rule SEC-001
```

### 3. Production Deployment
Refer to the comprehensive [Deployment Guide](docs/deployment.md) for Docker, Docker Compose, systemd, and cloud hosting instructions.

---

## 6. Project Layout

```text
ai-code-security-agent/
├── Cargo.toml                    # Root Cargo workspace manifest
├── crates/
│   ├── secscan-core/             # Rust AST parser, taint engine, rules, SARIF exporter
│   ├── secscan-nebius/           # Nebius Token Factory client & prompt engineering
│   ├── secscan-agent/            # Ephemeral sandbox validator & test runner
│   ├── secscan-cli/              # Command-line interface (`secscan`)
│   └── secscan-server/           # Axum REST API & embedded interactive Web UI
├── test-corpus/
│   ├── vulnerable-shop/          # Curated vulnerable repository with unit tests
│   └── secure-shop/              # Hardened reference application
├── docs/
│   ├── architecture.md           # System design & data-flow pipeline
│   ├── threat-model.md           # Prompt injection & sandbox security controls
│   └── nebius.md                 # Nebius Token Factory API specifications
├── Dockerfile                    # Multi-stage production container
├── docker-compose.yml            # Single-command deployment
└── LICENSE                       # Apache 2.0 Open Source License
```

---

## 7. License

Licensed under the [Apache License, Version 2.0](LICENSE).
