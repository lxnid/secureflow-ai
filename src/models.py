"""Pydantic models for data flow between agents.

These models define the contracts for findings, risk scores, fixes,
compliance evidence, and PR context that pass through the
Scanner → Intelligence → Remediation pipeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Priority(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ConfidenceTier(StrEnum):
    """Confidence-based routing tiers (core design decision).

    >90% → auto-suggest inline on PR
    70-90% → suggest with [Review Required]
    <70% → escalate to security team
    """

    AUTO_APPLY = "auto_apply"
    REVIEW_REQUIRED = "review_required"
    ESCALATE = "escalate"

    @classmethod
    def from_score(cls, confidence: float) -> ConfidenceTier:
        if confidence >= 0.9:
            return cls.AUTO_APPLY
        if confidence >= 0.7:
            return cls.REVIEW_REQUIRED
        return cls.ESCALATE


# --- Scanner Agent output ---


class Finding(BaseModel):
    """A single security finding detected by the Scanner Agent."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cwe_id: str = Field(description="CWE identifier, e.g. CWE-89")
    severity: Severity
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int | None = None
    code_snippet: str = ""
    vuln_type: str = Field(description="Normalized type: sql_injection, xss, hardcoded_secret, etc.")
    tool: str = Field(default="semgrep", description="Detection tool that found this")


# --- Intelligence Agent output ---


class RiskScore(BaseModel):
    """Multi-factor risk assessment produced by the Intelligence Agent."""

    priority: Priority
    rationale: str
    reachability: float = Field(ge=0, le=10, description="Is code path externally accessible?")
    data_sensitivity: float = Field(ge=0, le=10, description="Does it handle PII, payment, auth?")
    exploit_complexity: float = Field(ge=0, le=10, description="How easy to exploit?")
    existing_controls: float = Field(ge=0, le=10, description="Are there mitigating controls?")
    blast_radius: float = Field(ge=0, le=10, description="How many users/systems affected?")
    composite_score: float = Field(ge=0, le=10)

    @classmethod
    def compute_priority(cls, composite: float) -> Priority:
        if composite >= 8.0:
            return Priority.CRITICAL
        if composite >= 6.0:
            return Priority.HIGH
        if composite >= 4.0:
            return Priority.MEDIUM
        return Priority.LOW


class TeamPattern(BaseModel):
    """A historical fix pattern from the knowledge base."""

    vuln_type: str
    fix_pattern: str
    language: str
    framework: str = ""
    confidence: float = Field(ge=0, le=1)
    accepted_count: int = 0
    rejected_count: int = 0


class PrioritizedFinding(BaseModel):
    """A finding enriched with risk score and team context by the Intelligence Agent."""

    finding: Finding
    risk_score: RiskScore
    team_patterns: list[TeamPattern] = []
    compliance_frameworks: list[str] = []


# --- Remediation Agent output ---


class Fix(BaseModel):
    """A generated fix for a security finding."""

    finding_id: str
    fixed_code: str
    explanation: str
    confidence: float = Field(ge=0, le=1)
    is_valid: bool = False
    validation_errors: list[str] = []

    @computed_field
    @property
    def confidence_tier(self) -> ConfidenceTier:
        return ConfidenceTier.from_score(self.confidence)


class PRSuggestion(BaseModel):
    """An inline code suggestion to post on a PR diff."""

    path: str
    start_line: int
    end_line: int
    fixed_code: str
    explanation: str
    severity: Severity
    confidence: float
    confidence_tier: ConfidenceTier


# --- Compliance ---


class ComplianceRequirement(BaseModel):
    framework: str = Field(description="e.g. SOC2, PCI-DSS, OWASP")
    requirement: str = Field(description="e.g. CC6.1, 6.5.1, A03:2021")
    description: str


class ComplianceEvidence(BaseModel):
    """Audit-ready evidence document for a remediated vulnerability."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pr_number: int
    repo: str
    finding: Finding
    fix: Fix
    requirements_addressed: list[ComplianceRequirement]
    status: str = "remediated"


# --- Workflow context ---


class PRContext(BaseModel):
    """Context about the pull request being analyzed."""

    repo: str = Field(description="Repository in owner/name format")
    pr_number: int
    head_sha: str
    base_branch: str = "main"
    diff: str = ""
    changed_files: list[str] = []


class WorkflowResult(BaseModel):
    """Complete result of the 3-agent pipeline for a single PR."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pr_context: PRContext
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "completed"
    scan_findings: list[Finding] = []
    prioritized_findings: list[PrioritizedFinding] = []
    fixes: list[Fix] = []
    evidence: list[ComplianceEvidence] = []
    duration_seconds: float = 0.0
