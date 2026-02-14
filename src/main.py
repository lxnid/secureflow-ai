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
    yield
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

    # 6. Trigger pipeline in background
    background_tasks.add_task(process_pr, repo, pr_number, head_sha)

    return {
        "status": "accepted",
        "repo": repo,
        "pr_number": pr_number,
    }


async def process_pr(repo: str, pr_number: int, head_sha: str) -> None:
    """Run the multi-agent security review pipeline for a PR.

    Currently uses the Scanner Agent only (Sprint 1).
    Sprint 2 will upgrade this to the full 3-agent orchestrator.
    """
    from src.agents.scanner import create_scanner_agent
    from src.plugins.github_plugin import GitHubPlugin

    start = time.monotonic()
    github = GitHubPlugin(settings.github_token)

    try:
        scanner = create_scanner_agent(settings)
        task_message = (
            f"Analyze pull request #{pr_number} in repository {repo}. "
            f"The head commit SHA is {head_sha}. "
            f"Scan all changed files for security vulnerabilities and return structured findings."
        )

        response = await scanner.get_response(messages=task_message)
        duration = time.monotonic() - start

        logger.info("Scanner completed for PR #%d in %.1fs", pr_number, duration)

        # Post findings to PR as a comment
        comment_body = _format_scanner_comment(response.content, duration)
        await github.post_summary_comment(repo, pr_number, comment_body)

    except Exception:
        duration = time.monotonic() - start
        logger.exception("Pipeline failed for PR #%d after %.1fs", pr_number, duration)

        # Post error comment so the developer isn't left waiting
        try:
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
    finally:
        await github.aclose()


def _format_scanner_comment(scanner_output: str, duration: float) -> str:
    """Format Scanner Agent output as a GitHub PR comment."""
    # Try to parse as JSON for structured formatting
    try:
        data = json.loads(scanner_output)
        findings = data.get("findings", [])
    except (json.JSONDecodeError, TypeError):
        # If not valid JSON, post the raw output
        return (
            "## :shield: SecureFlow AI — Security Intelligence Report\n\n"
            f"{scanner_output}\n\n"
            f"_Analysis completed in {duration:.1f}s_"
        )

    if not findings:
        return (
            "## :white_check_mark: SecureFlow AI — Security Intelligence Report\n\n"
            f"**No security issues found** in {data.get('files_scanned', 'the')} scanned files.\n\n"
            f"_Analysis completed in {duration:.1f}s_"
        )

    # Build structured report
    severity_icons = {
        "CRITICAL": ":red_circle:",
        "HIGH": ":orange_circle:",
        "MEDIUM": ":yellow_circle:",
        "LOW": ":white_circle:",
    }

    lines = [
        "## :shield: SecureFlow AI — Security Intelligence Report\n",
        f"**{len(findings)} security issue(s) detected** "
        f"in {data.get('files_scanned', '?')} scanned files.\n",
        "| Severity | Finding | Location |",
        "|----------|---------|----------|",
    ]

    for f in findings:
        icon = severity_icons.get(f.get("severity", "MEDIUM"), ":white_circle:")
        title = f.get("title", "Unknown")
        file_path = f.get("file_path", "?")
        line = f.get("line_start", "?")
        lines.append(f"| {icon} **{f.get('severity', '?')}** | {title} | `{file_path}:{line}` |")

    lines.append("")

    # Detailed findings
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f.get('title', 'Finding')}")
        lines.append(f"**Severity:** {f.get('severity', '?')} | **CWE:** {f.get('cwe_id', '?')} | **Type:** {f.get('vuln_type', '?')}\n")
        lines.append(f"{f.get('description', '')}\n")
        if f.get("code_snippet"):
            lines.append(f"```\n{f['code_snippet']}\n```\n")

    lines.append(f"\n_Analysis completed in {duration:.1f}s | Powered by SecureFlow AI_")

    return "\n".join(lines)
