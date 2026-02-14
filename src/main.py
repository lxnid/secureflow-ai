"""FastAPI webhook receiver — entry point for SecureFlow AI.

Receives GitHub webhook events, validates signatures, and triggers
the multi-agent security review pipeline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

from src.config import Settings

# Cosmos DB import — used for the knowledge base (patterns, evidence)
try:
    from azure.cosmos.aio import CosmosClient
except ImportError:
    CosmosClient = None  # type: ignore[assignment,misc]

logger = logging.getLogger("secureflow")

settings = Settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup, clean up on shutdown."""
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )
    logger.info("SecureFlow AI starting up")

    # Initialize Cosmos DB client for knowledge base (patterns, evidence)
    cosmos_client = None
    if CosmosClient and settings.cosmos_endpoint and settings.cosmos_key:
        try:
            cosmos_client = CosmosClient(
                settings.cosmos_endpoint, {"masterKey": settings.cosmos_key},
            )
            logger.info("Cosmos DB client initialized")
        except Exception as exc:
            logger.warning("Failed to initialize Cosmos DB client: %s", exc)
    app.state.cosmos_client = cosmos_client

    yield

    # Clean up Cosmos DB client
    if cosmos_client is not None:
        try:
            await cosmos_client.close()
        except Exception:
            pass
    logger.info("SecureFlow AI shutting down")


app = FastAPI(
    title="SecureFlow AI",
    description="AI-powered multi-agent DevSecOps intelligence platform",
    version="0.1.0",
    lifespan=lifespan,
)


def _verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature (X-Hub-Signature-256)."""
    expected = "sha256=" + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/webhook", status_code=202)
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Receive GitHub webhook events and trigger the security review pipeline."""
    # 1. Read raw body for signature verification
    body = await request.body()

    # 2. Verify webhook signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(body, signature, settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 3. Check event type
    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return {"status": "ignored", "reason": f"Event type '{event}' not handled"}

    # 4. Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    if action not in ("opened", "synchronize"):
        return {"status": "ignored", "reason": f"Action '{action}' not handled"}

    # 5. Extract PR details with validation
    try:
        pr = payload["pull_request"]
        repo = payload["repository"]["full_name"]
        pr_number = pr["number"]
        head_sha = pr["head"]["sha"]
    except (KeyError, TypeError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid payload structure: missing {e}")

    logger.info(
        "Processing PR #%d on %s (action=%s, sha=%s)",
        pr_number, repo, action, head_sha[:8],
    )

    # 6. Trigger pipeline in background (pass Cosmos client for knowledge base)
    cosmos_client = getattr(request.app.state, "cosmos_client", None)
    background_tasks.add_task(process_pr, repo, pr_number, head_sha, cosmos_client)

    return {
        "status": "accepted",
        "repo": repo,
        "pr_number": pr_number,
    }


async def process_pr(
    repo: str, pr_number: int, head_sha: str, cosmos_client=None,
) -> None:
    """Run the full 3-agent security review pipeline for a PR.

    Pipeline: Scanner → Intelligence → Remediation
    The Remediation Agent posts inline suggestions and comments directly
    to the PR via its GitHubPlugin. If the pipeline fails, we post
    a fallback error comment.
    """
    from src.orchestrator import SecurityReviewOrchestrator
    from src.plugins.github_plugin import GitHubPlugin

    start = time.monotonic()

    try:
        orchestrator = SecurityReviewOrchestrator(settings, cosmos_client=cosmos_client)
        result = await orchestrator.analyze_pr(repo, pr_number, head_sha)
        duration = time.monotonic() - start

        logger.info(
            "Pipeline completed for PR #%d in %.1fs (mode=%s)",
            pr_number, duration, result.get("orchestration_mode", "unknown"),
        )

        # The Remediation Agent already posts inline suggestions to the PR.
        # Post a summary comment with the full report as well.
        async with GitHubPlugin(settings.github_token) as github:
            comment_body = _format_pipeline_comment(result, duration)
            await github.post_summary_comment(repo, pr_number, comment_body)

    except Exception:
        duration = time.monotonic() - start
        logger.exception("Pipeline failed for PR #%d after %.1fs", pr_number, duration)

        # Post error comment so the developer isn't left waiting
        try:
            async with GitHubPlugin(settings.github_token) as github:
                await github.post_summary_comment(
                    repo,
                    pr_number,
                    (
                        "## :rotating_light: SecureFlow AI — Analysis Error\n\n"
                        "An error occurred while analyzing this pull request. "
                        "The security team has been notified.\n\n"
                        f"_Analysis duration: {duration:.1f}s_"
                    ),
                )
        except Exception:
            logger.exception("Failed to post error comment on PR #%d", pr_number)


def _format_pipeline_comment(result: dict, duration: float) -> str:
    """Format the full pipeline result as a GitHub PR comment."""
    severity_icons = {
        "CRITICAL": ":red_circle:",
        "HIGH": ":orange_circle:",
        "MEDIUM": ":yellow_circle:",
        "LOW": ":white_circle:",
    }

    # Handle unparseable output
    if result.get("parse_error"):
        raw = result.get("raw_output", "")
        return (
            "## :shield: SecureFlow AI — Security Intelligence Report\n\n"
            f"{raw[:3000]}\n\n"
            f"_Analysis completed in {duration:.1f}s_"
        )

    # Extract data from orchestrator result
    fixes = result.get("fixes", [])
    summary = result.get("summary", "")
    escalations = result.get("escalation_issues", [])
    mode = result.get("orchestration_mode", "unknown")

    # Also handle results that come through in the _raw_stages format
    prioritized = []
    raw_stages = result.get("_raw_stages", {})
    if raw_stages.get("intelligence"):
        try:
            intel_data = json.loads(raw_stages["intelligence"])
            prioritized = intel_data.get("prioritized_findings", [])
        except (json.JSONDecodeError, TypeError):
            pass

    # If we have no structured data at all, use the summary
    if not fixes and not prioritized and not summary:
        return (
            "## :white_check_mark: SecureFlow AI — Security Intelligence Report\n\n"
            "**No actionable security issues found.**\n\n"
            f"_Analysis completed in {duration:.1f}s | "
            f"Pipeline mode: {mode} | Powered by SecureFlow AI_"
        )

    lines = [
        "## :shield: SecureFlow AI — Security Intelligence Report\n",
    ]

    # Fixes summary table
    if fixes:
        tier_counts = {"auto_apply": 0, "review_required": 0, "escalate": 0}
        for fix in fixes:
            tier = fix.get("tier", "escalate")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        lines.append(f"**{len(fixes)} fix(es) generated** | ")
        parts = []
        if tier_counts["auto_apply"]:
            parts.append(f":white_check_mark: {tier_counts['auto_apply']} auto-applicable")
        if tier_counts["review_required"]:
            parts.append(f":warning: {tier_counts['review_required']} review required")
        if tier_counts["escalate"]:
            parts.append(f":rotating_light: {tier_counts['escalate']} escalated")
        lines[-1] += " | ".join(parts)
        lines.append("")

        lines.extend(["| Severity | Finding | Confidence | Action |", "|----------|---------|------------|--------|"])
        for fix in fixes:
            severity = fix.get("severity", "MEDIUM").upper()
            icon = severity_icons.get(severity, ":white_circle:")
            file_path = fix.get("file_path", "?")
            confidence = fix.get("confidence", 0)
            tier = fix.get("tier", "escalate")
            tier_label = {"auto_apply": "Auto-Apply", "review_required": "Review", "escalate": "Escalated"}.get(tier, tier)
            lines.append(
                f"| {icon} **{severity}** | `{file_path}` | {confidence:.0%} | {tier_label} |"
            )
        lines.append("")

    # Prioritized findings detail (from intelligence stage)
    if prioritized:
        lines.append("### Prioritized Findings\n")
        for i, pf in enumerate(prioritized, 1):
            finding = pf.get("finding", pf)
            risk = pf.get("risk_score", {})
            impact = pf.get("business_impact", "")
            title = finding.get("title", "Finding")
            severity = finding.get("severity", "?")
            cwe = finding.get("cwe_id", "?")
            score = risk.get("composite_score", "?")
            lines.append(f"**{i}. {title}** — {severity} | {cwe} | Risk: {score}/10")
            if impact:
                lines.append(f"> {impact}")
            lines.append("")

    # Escalation issues
    if escalations:
        lines.append("### :rotating_light: Escalated Issues\n")
        for esc in escalations:
            lines.append(f"- [{esc}]({esc})")
        lines.append("")

    # Summary
    if summary:
        lines.append(f"---\n{summary}\n")

    lines.append(
        f"_Analysis completed in {duration:.1f}s | "
        f"Pipeline: 3-agent sequential ({mode}) | "
        f"Powered by SecureFlow AI_"
    )

    return "\n".join(lines)
