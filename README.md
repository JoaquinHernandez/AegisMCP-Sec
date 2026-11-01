
# AegisMCP-Sec 🛡️

**AegisMCP-Sec** is an open-source security static analysis and defensive auditing engine for AI Agents, Large Language Models (LLMs), and Model Context Protocol (MCP) ecosystems. 
<img width="1024" height="572" alt="image" src="https://github.com/user-attachments/assets/f244ea33-1cfc-4b76-9b61-48a64f6ae027" />

It audits tool definitions, prevents prompt poisoning, verifies parameter agency boundaries, and enforces schema integrity to prevent runtime drift attacks (rug pulls).

---

## ⚡ Threat Vectors Audited

* **Tool Definition Poisoning (OWASP LLM07):** Identifies hidden instructions, prompt overrides, or adversarial directives embedded within tool descriptions and schema metadata.
* **Excessive Agency & Remote Execution (OWASP LLM08):** Flags dangerous capabilities (shell execution, code eval, direct terminal invocation) requiring strict isolation or Human-in-the-Loop (HITL) gates.
* **Unconstrained Parameter Boundaries:** Highlights dynamic string parameters lacking validation controls (`pattern`, `enum`, or `maxLength`), leaving room for parameter-level injection.
* **Dynamic Rug Pulls & Schema Drift:** Calculates deterministic cryptographic hashes (SHA-256) of tool schemas to detect unauthorized runtime changes.
* **Response Hygiene & Secret Leakage (OWASP LLM06):** Scans model output for canary tokens, API keys, or private system prompt leakage.

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone [https://github.com/your-username/aegis-mcp-sec.git](https://github.com/your-username/aegis-mcp-sec.git)
cd aegis-mcp-sec

Compute Baseline Hash
Establish a cryptographic baseline for your toolchain to prevent dynamic mutation:

Bash
python aegis_mcp_sec.py --manifest test_manifest.json --compute-hash
3. Run the Audit Suite
Audit the configuration and generate a SARIF report for integration into CI/CD security gates:

Bash
python aegis_mcp_sec.py --manifest test_manifest.json --sarif results.sarif
4. Audit Output for Data Leakage
Scan agent responses for sensitive string patterns or canary token leakage:

Bash
python aegis_mcp_sec.py --audit-output "Processed request with secret CANARY_9921_ALPHA" --canaries CANARY_9921_ALPHA
