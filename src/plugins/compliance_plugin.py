"""Semantic Kernel plugin for compliance mapping and evidence generation.

Maps CWE vulnerability IDs to regulatory/compliance frameworks
(SOC2, PCI-DSS, OWASP Top 10, HIPAA) and generates audit-ready
evidence documents stored in Cosmos DB.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.compliance")

# CWE → compliance framework mapping
# Each CWE maps to one or more framework requirements with descriptions
_COMPLIANCE_MAP: dict[str, list[dict[str, str]]] = {
    "CWE-89": [
        {"framework": "SOC2", "requirement": "CC6.1", "description": "Logical and physical access controls — prevent unauthorized data access via injection"},
        {"framework": "PCI-DSS", "requirement": "6.5.1", "description": "Injection flaws, particularly SQL injection"},
        {"framework": "OWASP", "requirement": "A03:2021", "description": "Injection — SQL, NoSQL, OS, LDAP injection"},
    ],
    "CWE-79": [
        {"framework": "OWASP", "requirement": "A03:2021", "description": "Injection — Cross-Site Scripting (XSS)"},
        {"framework": "PCI-DSS", "requirement": "6.5.7", "description": "Cross-site scripting (XSS)"},
        {"framework": "SOC2", "requirement": "CC6.1", "description": "Logical access controls — prevent XSS-based session hijacking"},
    ],
    "CWE-798": [
        {"framework": "SOC2", "requirement": "CC6.1", "description": "Credential management — no hardcoded secrets in source"},
        {"framework": "PCI-DSS", "requirement": "3.4", "description": "Render PAN unreadable anywhere it is stored"},
        {"framework": "PCI-DSS", "requirement": "8.2.1", "description": "Strong cryptography for credential storage"},
        {"framework": "HIPAA", "requirement": "164.312(a)(1)", "description": "Access control — unique user identification"},
    ],
    "CWE-78": [
        {"framework": "OWASP", "requirement": "A03:2021", "description": "Injection — OS Command Injection"},
        {"framework": "SOC2", "requirement": "CC6.1", "description": "Prevent unauthorized system command execution"},
    ],
    "CWE-22": [
        {"framework": "OWASP", "requirement": "A01:2021", "description": "Broken Access Control — Path Traversal"},
        {"framework": "PCI-DSS", "requirement": "6.5.8", "description": "Improper access control"},
    ],
    "CWE-918": [
        {"framework": "OWASP", "requirement": "A10:2021", "description": "Server-Side Request Forgery (SSRF)"},
        {"framework": "SOC2", "requirement": "CC6.6", "description": "System boundary protection"},
    ],
    "CWE-502": [
        {"framework": "OWASP", "requirement": "A08:2021", "description": "Software and Data Integrity Failures — Insecure Deserialization"},
        {"framework": "SOC2", "requirement": "CC7.2", "description": "System integrity monitoring"},
    ],
    "CWE-327": [
        {"framework": "PCI-DSS", "requirement": "4.1", "description": "Use strong cryptography for data in transit"},
        {"framework": "HIPAA", "requirement": "164.312(e)(1)", "description": "Transmission security — encryption"},
        {"framework": "SOC2", "requirement": "CC6.7", "description": "Encryption of data in transit"},
    ],
    "CWE-326": [
        {"framework": "PCI-DSS", "requirement": "4.1", "description": "Strong cryptography and security protocols"},
        {"framework": "SOC2", "requirement": "CC6.7", "description": "Encryption controls"},
    ],
    "CWE-601": [
        {"framework": "OWASP", "requirement": "A01:2021", "description": "Broken Access Control — Open Redirect"},
    ],
    "CWE-611": [
        {"framework": "OWASP", "requirement": "A05:2021", "description": "Security Misconfiguration — XXE"},
    ],
    "CWE-1035": [
        {"framework": "OWASP", "requirement": "A06:2021", "description": "Vulnerable and Outdated Components"},
        {"framework": "PCI-DSS", "requirement": "6.2", "description": "Install vendor-supplied security patches within one month"},
    ],
    "CWE-916": [
        {"framework": "PCI-DSS", "requirement": "8.2.1", "description": "Strong cryptography for password storage"},
        {"framework": "OWASP", "requirement": "A02:2021", "description": "Cryptographic Failures — Weak password hashing"},
    ],
    "CWE-352": [
        {"framework": "OWASP", "requirement": "A01:2021", "description": "Broken Access Control — CSRF"},
        {"framework": "PCI-DSS", "requirement": "6.5.9", "description": "Cross-site request forgery"},
    ],
}


class CompliancePlugin:
    """Kernel plugin for compliance mapping and evidence generation."""

    def __init__(self, cosmos_client=None, database_name: str = "secureflow"):
        self._cosmos_client = cosmos_client
        self._database_name = database_name

    @kernel_function(
        description="Map a CWE vulnerability ID to applicable compliance frameworks (SOC2, PCI-DSS, OWASP, HIPAA)"
    )
    async def map_compliance(
        self,
        cwe_id: Annotated[str, "CWE identifier (e.g. CWE-89, CWE-79, CWE-798)"],
    ) -> Annotated[str, "JSON array of compliance requirements this CWE violates"]:
        """Look up which compliance frameworks are affected by a given CWE."""
        cwe_upper = cwe_id.upper().strip()
        requirements = _COMPLIANCE_MAP.get(cwe_upper, [])

        if not requirements:
            return json.dumps({
                "cwe_id": cwe_upper,
                "requirements": [],
                "message": f"No compliance mapping found for {cwe_upper}. "
                           "This does not mean the issue is not important — "
                           "it may still violate internal security policies.",
            })

        return json.dumps({
            "cwe_id": cwe_upper,
            "requirements": requirements,
            "frameworks_affected": list({r["framework"] for r in requirements}),
        })

    @kernel_function(
        description="Generate an audit-ready compliance evidence document for a remediated vulnerability and store it in Cosmos DB"
    )
    async def generate_evidence(
        self,
        cwe_id: Annotated[str, "CWE identifier"],
        finding_title: Annotated[str, "Title of the security finding"],
        finding_severity: Annotated[str, "Severity: CRITICAL, HIGH, MEDIUM, LOW"],
        fix_explanation: Annotated[str, "Explanation of how the vulnerability was fixed"],
        fix_confidence: Annotated[float, "Confidence score of the fix (0.0-1.0)"],
        pr_number: Annotated[int, "Pull request number"],
        repo: Annotated[str, "Repository full name (owner/repo)"],
        file_path: Annotated[str, "File path where the vulnerability was found"],
    ) -> Annotated[str, "JSON evidence document with compliance mapping"]:
        """Create a structured evidence document and persist to Cosmos DB."""
        cwe_upper = cwe_id.upper().strip()
        requirements = _COMPLIANCE_MAP.get(cwe_upper, [])

        evidence = {
            "id": str(uuid.uuid4()),
            "type": "compliance_evidence",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pr_number": pr_number,
            "repo": repo,
            "finding": {
                "cwe_id": cwe_upper,
                "title": finding_title,
                "severity": finding_severity,
                "file_path": file_path,
            },
            "remediation": {
                "fix_explanation": fix_explanation,
                "confidence": fix_confidence,
                "tier": (
                    "auto_apply" if fix_confidence >= 0.9
                    else "review_required" if fix_confidence >= 0.7
                    else "escalate"
                ),
            },
            "compliance": {
                "requirements_addressed": requirements,
                "frameworks_affected": list({r["framework"] for r in requirements}),
            },
            "status": "remediated" if fix_confidence >= 0.7 else "pending_review",
            "audit_trail": {
                "detected_by": "SecureFlow AI Scanner Agent",
                "prioritized_by": "SecureFlow AI Intelligence Agent",
                "remediated_by": "SecureFlow AI Remediation Agent",
                "pr_link": f"https://github.com/{repo}/pull/{pr_number}",
            },
        }

        # Persist to Cosmos DB evidence container if available
        if self._cosmos_client:
            try:
                db = self._cosmos_client.get_database_client(self._database_name)
                container = db.get_container_client("evidence")
                await container.upsert_item(evidence)
                evidence["persisted"] = True
                logger.info(
                    "Compliance evidence stored for %s in PR #%d (%d frameworks)",
                    cwe_upper, pr_number, len(requirements),
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to persist evidence to Cosmos DB: %s", e)
                evidence["persisted"] = False
                evidence["persist_error"] = str(e)
        else:
            evidence["persisted"] = False

        return json.dumps(evidence)

    @kernel_function(
        description="Get a compliance summary for all findings in a PR, listing all affected frameworks and requirements"
    )
    async def get_compliance_summary(
        self,
        findings_json: Annotated[str, "JSON array of findings with cwe_id fields"],
    ) -> Annotated[str, "JSON compliance summary with affected frameworks and requirement counts"]:
        """Aggregate compliance impact across multiple findings."""
        try:
            findings = json.loads(findings_json)
        except (json.JSONDecodeError, TypeError):
            return json.dumps({"error": "Invalid findings JSON"})

        all_requirements: list[dict] = []
        frameworks: dict[str, set[str]] = {}
        unmapped_cwes: list[str] = []

        for finding in findings:
            cwe = finding.get("cwe_id", "").upper().strip()
            if not cwe:
                continue
            reqs = _COMPLIANCE_MAP.get(cwe, [])
            if not reqs:
                unmapped_cwes.append(cwe)
                continue
            for req in reqs:
                all_requirements.append({**req, "cwe_id": cwe})
                fw = req["framework"]
                if fw not in frameworks:
                    frameworks[fw] = set()
                frameworks[fw].add(req["requirement"])

        summary = {
            "total_findings": len(findings),
            "compliance_relevant": len(findings) - len(unmapped_cwes),
            "frameworks_affected": {
                fw: {"requirements": sorted(reqs), "count": len(reqs)}
                for fw, reqs in sorted(frameworks.items())
            },
            "all_requirements": all_requirements,
            "unmapped_cwes": unmapped_cwes,
        }

        return json.dumps(summary)
