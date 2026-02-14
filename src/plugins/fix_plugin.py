"""Semantic Kernel plugin for generating, validating, and scoring security fixes.

Generates context-aware fixes using Azure OpenAI, validates them with
AST parsing, and assigns confidence scores for the routing pipeline.
"""

from __future__ import annotations

import ast
import json
import logging
from typing import Annotated

from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.fix")

# Base confidence by vulnerability type — well-understood vulns get higher base
_BASE_CONFIDENCE = {
    "sql_injection": 0.85,
    "sqli": 0.85,
    "hardcoded_secret": 0.90,
    "hardcoded_password": 0.90,
    "hardcoded_credentials": 0.90,
    "xss": 0.78,
    "cross_site_scripting": 0.78,
    "path_traversal": 0.80,
    "command_injection": 0.75,
    "os_command_injection": 0.75,
    "ssrf": 0.65,
    "deserialization": 0.60,
    "insecure_hash": 0.82,
    "weak_crypto": 0.82,
    "xxe": 0.70,
    "open_redirect": 0.75,
    "vulnerable_dependency": 0.70,
}


class FixGeneratorPlugin:
    """Kernel plugin for generating and validating security fixes."""

    @kernel_function(
        description="Generate a security fix for vulnerable code, optionally matching team patterns"
    )
    async def generate_fix(
        self,
        vulnerable_code: Annotated[str, "The vulnerable code snippet"],
        vuln_type: Annotated[str, "Type of vulnerability (e.g. sql_injection, xss)"],
        language: Annotated[str, "Programming language"],
        team_pattern: Annotated[str, "Team's preferred fix pattern from historical data (optional)"] = "",
        file_context: Annotated[str, "Surrounding code or imports for context (optional)"] = "",
    ) -> Annotated[str, "JSON with fixed_code, explanation, and changes_made"]:
        """Return a fix object. The agent's LLM generates the actual fix code.

        This plugin structures the request and returns a template the agent
        fills in. The agent itself (backed by GPT-4o) does the code generation
        via its own reasoning — this plugin provides the scaffolding.
        """
        # Build a structured prompt the agent can use to reason about the fix
        fix_guidance = {
            "task": "generate_security_fix",
            "vulnerable_code": vulnerable_code,
            "vuln_type": vuln_type,
            "language": language,
            "team_pattern": team_pattern or "No team pattern available — use best practices",
            "file_context": file_context or "No additional context",
            "requirements": [
                "Eliminate the vulnerability completely",
                "Match the team's coding style if a pattern is provided",
                "Preserve existing functionality — do not change behavior",
                "Keep the fix minimal — change only what is necessary",
                "Use the language's idiomatic security patterns",
            ],
            "expected_output": {
                "fixed_code": "The corrected code that replaces the vulnerable snippet",
                "explanation": "Brief explanation of what was changed and why",
                "changes_made": ["List of specific changes made"],
            },
        }

        return json.dumps(fix_guidance)

    @kernel_function(
        description="Validate that a code fix is syntactically correct for the given language"
    )
    async def validate_fix(
        self,
        code: Annotated[str, "Fixed code to validate"],
        language: Annotated[str, "Programming language"],
    ) -> Annotated[str, "JSON with is_valid boolean and any syntax errors"]:
        """Validate fix syntax. Currently supports Python via ast.parse."""
        if language.lower() in ("python", "py"):
            try:
                ast.parse(code)
                return json.dumps({"is_valid": True, "errors": []})
            except SyntaxError as e:
                return json.dumps({
                    "is_valid": False,
                    "errors": [f"Line {e.lineno}: {e.msg}"],
                })

        if language.lower() in ("javascript", "typescript", "js", "ts"):
            # Basic structural validation — check balanced braces/brackets
            errors = _check_balanced(code)
            if errors:
                return json.dumps({"is_valid": False, "errors": errors})
            return json.dumps({"is_valid": True, "errors": []})

        # For other languages, skip validation (assume valid)
        return json.dumps({
            "is_valid": True,
            "errors": [],
            "note": f"No syntax validator available for {language} — assuming valid",
        })

    @kernel_function(
        description="Assess confidence level of a generated fix based on vulnerability type, validation result, and team pattern availability"
    )
    async def assess_confidence(
        self,
        vuln_type: Annotated[str, "Vulnerability type"],
        fix_is_valid: Annotated[bool, "Whether the fix passed syntax validation"],
        has_team_pattern: Annotated[bool, "Whether a team fix pattern was available"],
        code_complexity: Annotated[str, "Complexity estimate: simple, moderate, or complex"] = "moderate",
    ) -> Annotated[str, "JSON with confidence score 0.0-1.0, tier, and reasoning"]:
        """Compute confidence score using heuristics.

        Base confidence by vuln type, then adjust:
        +0.05 if team pattern available
        +0.03 if fix validated successfully
        -0.10 if code is complex
        -0.15 if code is very complex
        """
        base = _BASE_CONFIDENCE.get(vuln_type.lower(), 0.65)

        adjustments: list[str] = []

        if has_team_pattern:
            base += 0.05
            adjustments.append("+0.05 team pattern match")

        if fix_is_valid:
            base += 0.03
            adjustments.append("+0.03 passed syntax validation")
        else:
            base -= 0.10
            adjustments.append("-0.10 failed syntax validation")

        complexity = code_complexity.lower().strip()
        if complexity == "complex":
            base -= 0.10
            adjustments.append("-0.10 complex code change")
        elif complexity == "simple":
            base += 0.05
            adjustments.append("+0.05 simple code change")

        # Clamp to [0.0, 1.0]
        confidence = max(0.0, min(1.0, base))

        # Determine tier
        if confidence >= 0.9:
            tier = "auto_apply"
            tier_label = "Auto-Applicable"
        elif confidence >= 0.7:
            tier = "review_required"
            tier_label = "Review Required"
        else:
            tier = "escalate"
            tier_label = "Needs Expert Review"

        reasoning = (
            f"Base confidence for {vuln_type}: {_BASE_CONFIDENCE.get(vuln_type.lower(), 0.65):.2f}. "
            f"Adjustments: {', '.join(adjustments)}. "
            f"Final: {confidence:.2f} → {tier_label}."
        )

        return json.dumps({
            "confidence": round(confidence, 2),
            "tier": tier,
            "tier_label": tier_label,
            "reasoning": reasoning,
        })


def _check_balanced(code: str) -> list[str]:
    """Basic balanced bracket check for JS/TS code."""
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    errors: list[str] = []

    for i, ch in enumerate(code):
        if ch in pairs:
            stack.append(ch)
        elif ch in pairs.values():
            if not stack:
                errors.append(f"Char {i}: unexpected closing '{ch}'")
            else:
                expected = pairs[stack.pop()]
                if ch != expected:
                    errors.append(f"Char {i}: expected '{expected}', got '{ch}'")

    if stack:
        errors.append(f"Unclosed brackets: {''.join(stack)}")

    return errors
