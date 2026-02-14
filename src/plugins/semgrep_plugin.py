"""Semantic Kernel plugin wrapping Semgrep SAST scanner.

Runs Semgrep as an async subprocess to avoid blocking the event loop.
Results are normalized to the Finding schema for downstream agents.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Annotated

from semantic_kernel.functions import kernel_function

# Mapping of Semgrep severity → our Severity enum values
_SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "MEDIUM",
    "NOTE": "LOW",
}

# Best-effort mapping of Semgrep rule IDs to CWE IDs
_CWE_MAP = {
    "sql-injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cross-site-scripting": "CWE-79",
    "hardcoded-secret": "CWE-798",
    "hardcoded-password": "CWE-798",
    "hardcoded-credentials": "CWE-798",
    "path-traversal": "CWE-22",
    "command-injection": "CWE-78",
    "os-command-injection": "CWE-78",
    "ssrf": "CWE-918",
    "open-redirect": "CWE-601",
    "deserialization": "CWE-502",
    "insecure-hash": "CWE-327",
    "weak-crypto": "CWE-327",
    "xxe": "CWE-611",
}

# Allowed file extensions — prevents path traversal via language param
_EXT_MAP = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "go": ".go",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
    "c": ".c",
    "cpp": ".cpp",
}

# Allowed manifest filenames for dependency scanning
_ALLOWED_MANIFESTS = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "pyproject.toml",
    "poetry.lock",
    "composer.json",
    "composer.lock",
}


def _extract_cwe(result: dict) -> str:
    """Extract CWE from Semgrep metadata first, then fall back to rule ID inference."""
    # Semgrep often includes CWE in result metadata
    metadata = result.get("extra", {}).get("metadata", {})
    cwe_field = metadata.get("cwe")
    if cwe_field:
        if isinstance(cwe_field, list) and cwe_field:
            cwe = str(cwe_field[0])
        else:
            cwe = str(cwe_field)
        # Normalize: ensure "CWE-" prefix
        if cwe.startswith("CWE-"):
            return cwe
        if cwe.isdigit():
            return f"CWE-{cwe}"

    # Fall back to rule ID keyword matching
    rule_id = result.get("check_id", "").lower()
    for key, cwe in _CWE_MAP.items():
        if key in rule_id:
            return cwe
    return "CWE-Unknown"


def _infer_vuln_type(result: dict) -> str:
    """Normalize to a short vulnerability type from metadata or rule ID."""
    rule_id = result.get("check_id", "").lower()
    for key in _CWE_MAP:
        if key in rule_id:
            return key.replace("-", "_")
    return "unknown"


def _normalize_findings(semgrep_json: dict) -> list[dict]:
    """Convert Semgrep JSON output to our Finding schema."""
    findings: list[dict] = []
    for result in semgrep_json.get("results", []):
        extra = result.get("extra", {})
        semgrep_severity = extra.get("severity", "INFO").upper()

        findings.append({
            "cwe_id": _extract_cwe(result),
            "severity": _SEVERITY_MAP.get(semgrep_severity, "MEDIUM"),
            "title": extra.get("message", result.get("check_id", "unknown"))[:120],
            "description": extra.get("message", ""),
            "file_path": result.get("path", ""),
            "line_start": result.get("start", {}).get("line", 0),
            "line_end": result.get("end", {}).get("line"),
            "code_snippet": extra.get("lines", ""),
            "vuln_type": _infer_vuln_type(result),
            "tool": "semgrep",
        })
    return findings


async def _run_subprocess(
    *cmd: str,
    timeout: int = 30,
    tool_name: str = "tool",
) -> tuple[bytes, bytes, int]:
    """Run a subprocess with proper timeout handling and zombie process cleanup.

    Returns (stdout, stderr, returncode). Raises RuntimeError on tool-not-found.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise RuntimeError(f"{tool_name} is not installed") from None

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # Kill the subprocess to prevent zombie processes
        proc.kill()
        await proc.wait()
        raise

    return stdout, stderr, proc.returncode


class SemgrepPlugin:
    """Semantic Kernel plugin for static application security testing."""

    @kernel_function(description="Run a SAST security scan on source code and return JSON findings")
    async def run_sast_scan(
        self,
        code: Annotated[str, "Source code to scan"],
        language: Annotated[str, "Programming language (python, javascript, java, go, ruby, etc.)"],
    ) -> Annotated[str, "JSON array of security findings"]:
        """Write code to a temp file, run Semgrep, and return normalized findings."""
        lang_key = language.lower().strip()
        if lang_key not in _EXT_MAP:
            return json.dumps({
                "error": f"Unsupported language: {language}. Supported: {', '.join(sorted(_EXT_MAP))}",
                "findings": [],
            })
        ext = _EXT_MAP[lang_key]

        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = Path(tmpdir) / f"scan_target{ext}"
            try:
                code_file.write_text(code)
            except OSError as e:
                return json.dumps({"error": f"Failed to write temp file: {e}", "findings": []})

            try:
                stdout, stderr, returncode = await _run_subprocess(
                    "semgrep", "scan", "--config", "auto", "--json", "--quiet", str(tmpdir),
                    timeout=30,
                    tool_name="Semgrep",
                )
            except RuntimeError as e:
                return json.dumps({"error": str(e), "findings": []})
            except asyncio.TimeoutError:
                return json.dumps({"error": "Semgrep scan timed out after 30 seconds", "findings": []})

            # returncode 1 means findings were found (not an error)
            if returncode not in (0, 1):
                return json.dumps({
                    "error": f"Semgrep exited with code {returncode}",
                    "stderr": stderr.decode(errors="replace")[:500],
                    "findings": [],
                })

            try:
                semgrep_output = json.loads(stdout.decode(errors="replace"))
            except json.JSONDecodeError:
                return json.dumps({"error": "Failed to parse Semgrep JSON output", "findings": []})

            findings = _normalize_findings(semgrep_output)
            return json.dumps({"findings": findings, "count": len(findings)})

    @kernel_function(description="Run a dependency vulnerability scan on a package manifest")
    async def scan_dependencies(
        self,
        manifest_content: Annotated[str, "Package manifest content (requirements.txt, package.json, etc.)"],
        manifest_type: Annotated[str, "Manifest filename: requirements.txt | package.json | pom.xml | go.mod"],
    ) -> Annotated[str, "JSON array of dependency vulnerabilities"]:
        """Write manifest to temp file, run Trivy, and return findings."""
        # Validate manifest filename to prevent path traversal
        if manifest_type not in _ALLOWED_MANIFESTS:
            return json.dumps({
                "error": f"Unsupported manifest type: {manifest_type}",
                "findings": [],
            })

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_file = Path(tmpdir) / manifest_type
            try:
                manifest_file.write_text(manifest_content)
            except OSError as e:
                return json.dumps({"error": f"Failed to write temp file: {e}", "findings": []})

            try:
                stdout, _stderr, returncode = await _run_subprocess(
                    "trivy", "fs", "--format", "json", "--quiet", str(tmpdir),
                    timeout=30,
                    tool_name="Trivy",
                )
            except RuntimeError as e:
                return json.dumps({"error": str(e), "findings": []})
            except asyncio.TimeoutError:
                return json.dumps({"error": "Trivy scan timed out after 30 seconds", "findings": []})

            if returncode != 0:
                return json.dumps({
                    "error": f"Trivy exited with code {returncode}",
                    "findings": [],
                })

            try:
                trivy_output = json.loads(stdout.decode(errors="replace"))
            except json.JSONDecodeError:
                return json.dumps({"error": "Failed to parse Trivy JSON output", "findings": []})

            findings: list[dict] = []
            for result in trivy_output.get("Results") or []:
                # Trivy may return Vulnerabilities as null instead of []
                vulns = result.get("Vulnerabilities")
                if not vulns:
                    continue
                for vuln in vulns:
                    findings.append({
                        "cwe_id": (vuln.get("CweIDs") or ["CWE-Unknown"])[0],
                        "severity": vuln.get("Severity", "MEDIUM").upper(),
                        "title": f"{vuln.get('PkgName', 'unknown')}@{vuln.get('InstalledVersion', '?')}: {vuln.get('VulnerabilityID', '')}",
                        "description": vuln.get("Description", ""),
                        "file_path": manifest_type,
                        "line_start": 0,
                        "vuln_type": "vulnerable_dependency",
                        "tool": "trivy",
                    })
            return json.dumps({"findings": findings, "count": len(findings)})
