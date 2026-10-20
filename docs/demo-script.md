# 3-Minute Hackathon Demo Video Script

**Target Time:** < 3 minutes (e.g. 2 min 45 sec)  
**Track:** Coding and Agentic Engineering Track  

---

### [0:00 - 0:25] The Problem & The Non-Obvious Insight
* **Visual:** Speaker camera or split-screen showing slides / code.
* **Audio:**
  > "Most AI security scanners today suffer from a major flaw: they dump raw code into an LLM and ask 'Is this secure?'. This leads to hallucinations, false positives, and context window limits.
  >
  > Today we're introducing **SecScan AI**: an autonomous security engineering agent built on a fundamentally different principle: **The AI is not the security scanner.**
  > A deterministic Rust static-analysis engine discovers evidence; NVIDIA Nemotron on Nebius Token Factory reasons over that evidence; and a sandboxed agent loop repairs and verifies the fix."

---

### [0:25 - 1:00] Deterministic Static Analysis & Taint Graph
* **Visual:** Open browser to `http://localhost:3000`. Click **Scan Repository** on `test-corpus/vulnerable-shop`.
* **Audio:**
  > "Let's scan our vulnerable ecommerce repository. In just 17 milliseconds, our Rust Tree-Sitter engine scans the Concrete Syntax Tree and detects 8 real vulnerabilities.
  > 
  > Notice the first finding: SQL Injection. Instead of just searching for the word 'SELECT', SecScan traces the exact intra-procedural taint flow: from the HTTP request source on line 38, propagating through variable assignment on line 42, directly into the database execution sink on line 43. Zero guesswork."

---

### [1:00 - 1:40] NVIDIA Nemotron Reasoning on Nebius Token Factory
* **Visual:** Click **Explain with Nemotron**. Show the response and the telemetry pill.
* **Audio:**
  > "Now, we bring in NVIDIA Nemotron through Nebius Token Factory. Notice our live telemetry: running on `nvidia/llama-3.1-nemotron-70b-instruct` with 180ms latency.
  >
  > Nemotron receives structured evidence encapsulated in strict untrusted data tags to prevent prompt injection. It analyzes the root cause, models how an adversary could exploit this parameter, and recommends an architectural fix tailored specifically to our Flask and SQLite stack."

---

### [1:40 - 2:25] Autonomous Agent Verification Loop (The "Wow" Moment)
* **Visual:** Click **Verify & Fix**. Show the 4-step checklist animating in real time.
* **Audio:**
  > "Here is where SecScan becomes a true coding agent. Instead of trusting an LLM patch blindly, SecScan invokes our autonomous validation loop:
  > 1. Nemotron generates a unified diff patch using parameterized queries.
  > 2. Our pre-patch safety guard verifies the diff doesn't introduce backdoors or dangerous primitives.
  > 3. The agent clones the repository into an isolated ephemeral sandbox.
  > 4. It executes the unit test suite inside the sandbox.
  > 5. Finally, it re-runs our Rust static analysis engine.
  >
  > All tests pass, the SQL injection is cleared, and the gate switches to: **VALIDATED — MERGE READY**."

---

### [2:25 - 2:45] CI/CD SARIF & Defense Controls
* **Visual:** Switch briefly to terminal, run `cargo run --bin secscan -- scan test-corpus/vulnerable-shop --format sarif`. Show clean SARIF output with codeFlows.
* **Audio:**
  > "SecScan also outputs standard OASIS SARIF 2.1.0 with complete thread flows, seamlessly plugging into GitHub Code Scanning and CI/CD pull request gates."

---

### [2:45 - 3:00] Conclusion & Nebius Stack
* **Visual:** Return to dashboard, show live Nebius telemetry badge.
* **Audio:**
  > "By combining the speed and mathematical certainty of Rust static analysis with the reasoning power of NVIDIA Nemotron on Nebius Token Factory, SecScan AI gives developers an autonomous security agent they can actually trust.
  > Check out our open-source repository on GitHub. Thank you!"
