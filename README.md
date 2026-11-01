
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


Set Up Environment
This tool uses Python 3.9+ standard libraries with no external binary requirements for the core CLI.

Bash
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
🛠️ Usage Examples
Audit an MCP Tool Manifest
Scan an MCP server's JSON manifest for policy violations, dangerous tools, and unconstrained inputs:

Bash
python aegis_mcp_sec.py --manifest examples/sample_mcp.json
Establish a Manifest Integrity Baseline
Generate a SHA-256 fingerprint of your tool manifest to pin against schema tampering:

Bash
python aegis_mcp_sec.py --manifest examples/sample_mcp.json --compute-hash
Run an integrity verification against your pinned hash:

Bash
python aegis_mcp_sec.py \
  --manifest examples/sample_mcp.json \
  --baseline-hash "a1b2c3d4e5f6..."
Output to SARIF for CI/CD Security Scanning
Export audit results directly to SARIF format for native integration into GitHub Actions and GitHub Advanced Security:

Bash
python aegis_mcp_sec.py \
  --manifest examples/sample_mcp.json \
  --sarif results.sarif
Audit Agent Output for Token & Secret Leaks
Audit agent responses for canary tokens or exposed credentials:

Bash
python aegis_mcp_sec.py \
  --audit-output "Execution complete. Canary: CANARY_ALPHA_991" \
  --canaries CANARY_ALPHA_991
