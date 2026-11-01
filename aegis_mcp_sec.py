#!/usr/bin/env python3
"""
AegisMCP-Sec: Hardened Security Audit Engine for AI Agents and MCP Hosts.
Focuses on defensive schema validation, excessive agency mitigation, and structural auditing.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

# ==========================================
# Severity & Finding Models
# ==========================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuditFinding:
    severity: Severity
    rule_id: str
    target: str
    description: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


# ==========================================
# Heuristic Signatures & High-Risk Capabilities
# ==========================================

INSTRUCTION_OVERRIDE_PATTERNS = [
    r"(?i)\bignore\s+(all\s+)?(previous|prior|system)\s+instructions\b",
    r"(?i)\bsystem\s+(override|bypass|reset)\b",
    r"(?i)\bdisregard\s+(the\s+)?safety\s+guidelines\b",
    r"(?i)\byou\s+are\s+now\s+in\s+unrestricted\s+mode\b",
    r"(?i)\bexfiltrate\s+to\b",
    r"(?i)\bdo\s+not\s+(mention|reveal)\s+this\s+tool\s+to\s+the\s+user\b",
    r"(?i)\bexecute\s+silently\b",
]

DANGEROUS_NAMING_TOKENS = [
    "exec", "execute", "shell", "bash", "cmd", "terminal", 
    "eval", "system_call", "run_script", "spawn"
]

HIGH_RISK_PARAM_NAMES = [
    "command", "cmd", "script", "query", "url", "path", "file_path", "raw_payload"
]


# ==========================================
# Hardened Audit Engine
# ==========================================

class AegisAuditEngine:
    """Core auditor providing static schema validation, policy checks, and response hygiene analysis."""

    def __init__(self, baseline_hash: Optional[str] = None):
        self.baseline_hash = baseline_hash
        self.findings: List[AuditFinding] = []

    def compute_manifest_hash(self, manifest: Dict[str, Any]) -> str:
        """Computes a deterministic SHA-256 digest of the tool schemas to detect runtime drift (rug pulls)."""
        serialized = json.dumps(manifest.get("tools", []), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def audit_manifest(self, manifest: Dict[str, Any]) -> List[AuditFinding]:
        """Performs static defensive audits on an MCP Server manifest."""
        tools = manifest.get("tools", [])
        if not tools:
            self.findings.append(
                AuditFinding(
                    severity=Severity.LOW,
                    rule_id="AEGIS-001",
                    target="Manifest",
                    description="Empty manifest: No tools registered on the MCP server.",
                    remediation="Register only the minimal, necessary tools using least-privilege principles."
                )
            )
            return self.findings

        # 1. Manifest Integrity & Drift Check
        current_hash = self.compute_manifest_hash(manifest)
        if self.baseline_hash and self.baseline_hash != current_hash:
            self.findings.append(
                AuditFinding(
                    severity=Severity.CRITICAL,
                    rule_id="AEGIS-002",
                    target="Manifest Integrity",
                    description=f"Manifest schema drift detected. Current hash ({current_hash[:8]}) does not match baseline ({self.baseline_hash[:8]}).",
                    remediation="Enforce cryptographic manifest pinning in client config to prevent dynamic schema poisoning (rug pulls)."
                )
            )

        for tool in tools:
            name = tool.get("name", "unnamed_tool")
            description = tool.get("description", "")
            input_schema = tool.get("inputSchema", {})

            # 2. Schema Poisoning & Hidden Instruction Detection
            for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
                if re.search(pattern, description):
                    self.findings.append(
                        AuditFinding(
                            severity=Severity.CRITICAL,
                            rule_id="AEGIS-003",
                            target=f"tool:{name}",
                            description=f"Instruction override pattern detected in description: matches '{pattern}'",
                            remediation="Sanitize tool documentation; remove meta-prompt instructions or directives directed at the LLM."
                        )
                    )

            # 3. Excessive Agency & High-Risk Execution Capabilities
            lower_name = name.lower()
            if any(token in lower_name for token in DANGEROUS_NAMING_TOKENS):
                self.findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        rule_id="AEGIS-004",
                        target=f"tool:{name}",
                        description="Tool provides direct process execution or system interaction capability.",
                        remediation="Apply strong human-in-the-loop (HITL) confirmation gates and isolate executions in ephemeral sandboxes."
                    )
                )

            # 4. Parameter Security Boundary Validation
            properties = input_schema.get("properties", {})
            required_params = set(input_schema.get("required", []))

            for param_name, param_meta in properties.items():
                p_type = param_meta.get("type", "unknown")
                p_desc = param_meta.get("description", "")

                # Check for parameter-level override prompts
                for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
                    if re.search(pattern, p_desc):
                        self.findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                rule_id="AEGIS-005",
                                target=f"param:{name}.{param_name}",
                                description=f"Adversarial instruction pattern found in parameter description: matches '{pattern}'",
                                remediation="Strip operational instructions from parameter descriptions."
                            )
                        )

                # Check for unbounded inputs on sensitive parameter names
                if param_name.lower() in HIGH_RISK_PARAM_NAMES:
                    has_enum = "enum" in param_meta
                    has_pattern = "pattern" in param_meta
                    has_length_limit = "maxLength" in param_meta

                    if p_type == "string" and not (has_enum or has_pattern or has_length_limit):
                        self.findings.append(
                            AuditFinding(
                                severity=Severity.MEDIUM,
                                rule_id="AEGIS-006",
                                target=f"param:{name}.{param_name}",
                                description=f"High-risk parameter '{param_name}' is unconstrained (missing pattern, enum, or maxLength validation).",
                                remediation="Constrain inputs via strict JSON Schema patterns (regex), enumerated allowlists, or hard length limits."
                            )
                        )

        return self.findings

    def audit_agent_response(self, response_text: str, canary_tokens: Optional[List[str]] = None) -> List[AuditFinding]:
        """Audits agent outputs for secret exposure, system prompt leakage, or canary compromise."""
        canary_tokens = canary_tokens or []
        for canary in canary_tokens:
            if canary and canary in response_text:
                self.findings.append(
                    AuditFinding(
                        severity=Severity.CRITICAL,
                        rule_id="AEGIS-007",
                        target="Agent Output",
                        description="Active canary token detected in agent output. Potential system prompt or memory exfiltration.",
                        remediation="Review system instructions, isolate data ingress channels, and implement egress content filtering."
                    )
                )

        # Baseline check for exposed environment indicators
        env_leak_patterns = [
            r"AKIA[0-9A-Z]{16}",                     # AWS Access Key ID
            r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",   # Bearer tokens
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY---"  # Private keys
        ]
        for pattern in env_leak_patterns:
            if re.search(pattern, response_text):
                self.findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        rule_id="AEGIS-008",
                        target="Agent Output",
                        description="Potential credential or cryptographic secret pattern detected in response.",
                        remediation="Apply automated output scrubbing on the host application before returning messages to context."
                    )
                )

        return self.findings


# ==========================================
# Reporting Utilities
# ==========================================

class SecurityReporter:
    @staticmethod
    def render_console(findings: List[AuditFinding]):
        colors = {
            Severity.CRITICAL: "\033[91m[CRITICAL]\033[0m",
            Severity.HIGH: "\033[31m[HIGH]\033[0m",
            Severity.MEDIUM: "\033[33m[MEDIUM]\033[0m",
            Severity.LOW: "\033[34m[LOW]\033[0m",
            Severity.INFO: "\033[90m[INFO]\033[0m",
        }

        print("\n" + "=" * 78)
        print("         AEGIS-MCP SECURITY AUDITING & POLICY ENGINE")
        print("=" * 78 + "\n")

        if not findings:
            print("\033[92m[PASS]\033[0m No policy violations, poisoning patterns, or unconstrained boundaries found.\n")
            return

        for finding in findings:
            tag = colors.get(finding.severity, f"[{finding.severity.value}]")
            print(f"{tag:<20} Target     : {finding.target}")
            print(f"  Rule ID    : {finding.rule_id}")
            print(f"  Description: {finding.description}")
            print(f"  Remediation: {finding.remediation}")
            print("-" * 78)

    @staticmethod
    def export_sarif(findings: List[AuditFinding], output_path: str):
        """Exports findings to SARIF format for ingestion into GitHub Advanced Security or other analyzers."""
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AegisMCP-Sec",
                            "informationUri": "https://github.com/example/aegis-mcp-sec",
                            "rules": [
                                {
                                    "id": f.rule_id,
                                    "shortDescription": {"text": f.rule_id},
                                    "defaultConfiguration": {"level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning"}
                                }
                                for f in findings
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning",
                            "message": {"text": f"{f.description} Remediation: {f.remediation}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.target}
                                    }
                                }
                            ]
                        }
                        for f in findings
                    ]
                }
            ]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)


# ==========================================
# CLI Entrypoint
# ==========================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AegisMCP-Sec: AI Agent and MCP Ecosystem Security Auditor")
    parser.add_argument("--manifest", type=str, help="Path to local MCP JSON manifest file")
    parser.add_argument("--baseline-hash", type=str, help="Expected SHA-256 hash of manifest tools schema")
    parser.add_argument("--compute-hash", action="store_true", help="Print the SHA-256 fingerprint of the provided manifest")
    parser.add_argument("--audit-output", type=str, help="Audit an agent response text or file for leaks")
    parser.add_argument("--canaries", type=str, nargs="*", default=[], help="Canary strings to verify against output")
    parser.add_argument("--sarif", type=str, help="Path to write SARIF audit output")
    return parser.parse_args()


def main():
    args = parse_args()
    engine = AegisAuditEngine(baseline_hash=args.baseline_hash)

    if args.manifest:
        if not os.path.exists(args.manifest):
            logging.error(f"Manifest file not found: {args.manifest}")
            sys.exit(1)

        try:
            with open(args.manifest, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
        except json.JSONDecodeError as err:
            logging.error(f"Invalid JSON in manifest: {err}")
            sys.exit(1)

        if args.compute_hash:
            digest = engine.compute_manifest_hash(manifest_data)
            print(f"Manifest Schema Fingerprint (SHA-256): {digest}")
            return

        engine.audit_manifest(manifest_data)

    if args.audit_output:
        raw_text = args.audit_output
        if os.path.exists(args.audit_output):
            with open(args.audit_output, "r", encoding="utf-8") as f:
                raw_text = f.read()
        engine.audit_agent_response(raw_text, canary_tokens=args.canaries)

    SecurityReporter.render_console(engine.findings)

    if args.sarif:
        SecurityReporter.export_sarif(engine.findings, args.sarif)
        print(f"SARIF report generated: {args.sarif}")


if __name__ == "__main__":
    main()
