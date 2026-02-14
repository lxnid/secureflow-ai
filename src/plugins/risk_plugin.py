"""Semantic Kernel plugin for multi-factor security risk assessment.

Scores findings across 5 dimensions: reachability, data sensitivity,
exploit complexity, existing controls, and blast radius. Returns a
composite score mapped to priority (CRITICAL/HIGH/MEDIUM/LOW).
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.risk")

# CWE-based exploit complexity defaults (higher = easier to exploit)
_CWE_COMPLEXITY = {
    "CWE-89": 8.5,   # SQL injection — well-known, tooling available
    "CWE-79": 7.0,   # XSS — common, moderate skill
    "CWE-78": 9.0,   # OS command injection — high impact, easy
    "CWE-22": 7.5,   # Path traversal — moderate
    "CWE-798": 9.5,  # Hardcoded credentials — trivial to exploit
    "CWE-918": 6.5,  # SSRF — needs some knowledge
    "CWE-502": 8.0,  # Deserialization — known gadget chains
    "CWE-327": 4.0,  # Weak crypto — needs specific conditions
    "CWE-611": 6.0,  # XXE — moderate complexity
    "CWE-601": 5.5,  # Open redirect — social engineering needed
}

# Keywords suggesting sensitive data handling
_SENSITIVE_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credit_card", "card_number", "ssn", "social_security",
    "payment", "billing", "auth", "session", "cookie",
    "private_key", "encryption_key", "jwt",
}

# Keywords suggesting public-facing code
_PUBLIC_KEYWORDS = {
    "route", "endpoint", "api", "controller", "handler", "view",
    "app.get", "app.post", "app.put", "app.delete",
    "@app.", "@router.", "@blueprint.",
    "public", "external", "webhook",
}


class RiskScorerPlugin:
    """Kernel plugin for multi-factor security risk scoring."""

    @kernel_function(
        description="Calculate a multi-factor risk score for a security finding, considering reachability, data sensitivity, exploit complexity, existing controls, and blast radius"
    )
    async def assess_risk(
        self,
        finding_json: Annotated[str, "JSON finding with cwe_id, severity, file_path, description, code_snippet"],
        code_context: Annotated[str, "Additional context: is it a public endpoint? handles PII? has existing controls? Provide as free-text description or JSON."],
    ) -> Annotated[str, "JSON risk assessment with priority, rationale, factor scores, and composite_score"]:
        try:
            finding = json.loads(finding_json)
        except (json.JSONDecodeError, TypeError):
            return json.dumps({"error": "Invalid finding JSON"})

        cwe_id = finding.get("cwe_id", "CWE-Unknown")
        description = finding.get("description", "").lower()
        code_snippet = finding.get("code_snippet", "").lower()
        file_path = finding.get("file_path", "").lower()
        combined_text = f"{description} {code_snippet} {file_path} {code_context.lower()}"

        # Factor 1: Reachability (0-10) — is the code externally accessible?
        reachability = 3.0  # default: internal code
        if any(kw in combined_text for kw in _PUBLIC_KEYWORDS):
            reachability = 8.0
        if "test" in file_path or "mock" in file_path:
            reachability = 1.0  # test code is low reachability

        # Factor 2: Data sensitivity (0-10) — does it handle sensitive data?
        data_sensitivity = 3.0
        sensitive_matches = sum(1 for kw in _SENSITIVE_KEYWORDS if kw in combined_text)
        if sensitive_matches >= 3:
            data_sensitivity = 9.0
        elif sensitive_matches >= 1:
            data_sensitivity = 6.5

        # Factor 3: Exploit complexity (0-10) — how easy to exploit?
        exploit_complexity = _CWE_COMPLEXITY.get(cwe_id, 5.0)

        # Factor 4: Existing controls (0-10) — are there mitigations?
        # Higher score = fewer controls = more risky
        existing_controls = 6.0  # default: assume no controls
        control_signals = [
            "sanitize", "escape", "validate", "parameterize",
            "prepared_statement", "orm", "csrf", "helmet",
            "rate_limit", "waf", "firewall",
        ]
        controls_found = sum(1 for s in control_signals if s in combined_text)
        if controls_found >= 2:
            existing_controls = 2.0  # good controls in place
        elif controls_found >= 1:
            existing_controls = 4.0

        # Factor 5: Blast radius (0-10) — impact scope
        blast_radius = 5.0
        if any(kw in combined_text for kw in ("database", "db", "sql", "query")):
            blast_radius = 8.0  # data store compromise
        if any(kw in combined_text for kw in ("admin", "root", "superuser")):
            blast_radius = 9.0  # privilege escalation
        if "payment" in combined_text or "billing" in combined_text:
            blast_radius = 9.5  # financial impact

        # Composite score (weighted average)
        composite = (
            reachability * 0.25
            + data_sensitivity * 0.20
            + exploit_complexity * 0.25
            + existing_controls * 0.15
            + blast_radius * 0.15
        )

        # Map to priority
        if composite >= 8.0:
            priority = "CRITICAL"
        elif composite >= 6.0:
            priority = "HIGH"
        elif composite >= 4.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        # Build rationale
        top_factors = sorted(
            [
                ("reachability", reachability),
                ("data_sensitivity", data_sensitivity),
                ("exploit_complexity", exploit_complexity),
                ("existing_controls", existing_controls),
                ("blast_radius", blast_radius),
            ],
            key=lambda x: x[1],
            reverse=True,
        )
        rationale = (
            f"{priority} priority ({composite:.1f}/10). "
            f"Top risk factors: {top_factors[0][0]} ({top_factors[0][1]:.1f}), "
            f"{top_factors[1][0]} ({top_factors[1][1]:.1f})."
        )

        return json.dumps({
            "priority": priority,
            "rationale": rationale,
            "reachability": round(reachability, 1),
            "data_sensitivity": round(data_sensitivity, 1),
            "exploit_complexity": round(exploit_complexity, 1),
            "existing_controls": round(existing_controls, 1),
            "blast_radius": round(blast_radius, 1),
            "composite_score": round(composite, 1),
            "cwe_id": cwe_id,
        })
