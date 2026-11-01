# AegisMCP-Sec


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
