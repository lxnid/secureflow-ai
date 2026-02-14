"""Multi-agent orchestrator for the security review pipeline.

Wires Scanner → Intelligence → Remediation using Semantic Kernel's
SequentialOrchestration (Option A) with a manual chaining fallback
(Option B) if the experimental orchestration API has issues.
"""

from __future__ import annotations

import json
import logging
import re
import time

from src.agents.intelligence import create_intelligence_agent
from src.agents.remediation import create_remediation_agent
from src.agents.scanner import create_scanner_agent
from src.config import Settings
from src.plugins.github_plugin import GitHubPlugin

logger = logging.getLogger("secureflow.orchestrator")


class SecurityReviewOrchestrator:
    """Orchestrates the 3-agent security review pipeline.

    Attempts SequentialOrchestration first (SK experimental API).
    Falls back to manual get_response() chaining if that fails.
    """

    def __init__(self, settings: Settings, cosmos_client=None):
        self._settings = settings
        self._cosmos_client = cosmos_client

    async def analyze_pr(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
    ) -> dict:
        """Run the full 3-agent pipeline for a PR.

        Returns a dict with scan_findings, prioritized_findings, fixes,
        and timing information.
        """
        start = time.monotonic()

        # Try Option A first, fall back to Option B
        try:
            result = await self._run_sequential_orchestration(repo, pr_number, head_sha)
            result["orchestration_mode"] = "sequential"
        except Exception as e:
            logger.warning(
                "SequentialOrchestration failed (%s), falling back to manual chaining",
                e,
            )
            result = await self._run_manual_chaining(repo, pr_number, head_sha)
            result["orchestration_mode"] = "manual"

        result["duration_seconds"] = round(time.monotonic() - start, 1)
        result["repo"] = repo
        result["pr_number"] = pr_number
        return result

    async def _run_sequential_orchestration(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
    ) -> dict:
        """Option A: Use SK SequentialOrchestration + InProcessRuntime."""
        from semantic_kernel.agents import SequentialOrchestration
        from semantic_kernel.agents.runtime import InProcessRuntime

        # Shared GitHubPlugin so all agents reuse one httpx connection pool
        github_plugin = GitHubPlugin(self._settings.github_token)
        try:
            scanner = create_scanner_agent(self._settings, github_plugin=github_plugin)
            intelligence = create_intelligence_agent(self._settings, self._cosmos_client)
            remediation = create_remediation_agent(self._settings, github_plugin=github_plugin)

            task_message = self._build_task_message(repo, pr_number, head_sha)

            orchestration = SequentialOrchestration(
                members=[scanner, intelligence, remediation],
            )
            runtime = InProcessRuntime()
            runtime.start()

            try:
                invocation = await orchestration.invoke(
                    task=task_message,
                    runtime=runtime,
                )
                final_response = await invocation.get(timeout=self._settings.agent_timeout_seconds * 3)
            finally:
                await runtime.stop_when_idle()

            return self._parse_final_response(
                final_response.content if hasattr(final_response, "content") else str(final_response),
            )
        finally:
            await github_plugin.aclose()

    async def _run_manual_chaining(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
    ) -> dict:
        """Option B: Manual chaining with get_response() — reliable fallback."""
        # Shared GitHubPlugin so Scanner + Remediation reuse one connection pool
        github_plugin = GitHubPlugin(self._settings.github_token)
        try:
            scanner = create_scanner_agent(self._settings, github_plugin=github_plugin)
            intelligence = create_intelligence_agent(self._settings, self._cosmos_client)
            remediation = create_remediation_agent(self._settings, github_plugin=github_plugin)

            task_message = self._build_task_message(repo, pr_number, head_sha)

            # Stage 1: Scanner
            logger.info("Stage 1/3: Scanner agent starting")
            scan_response = await scanner.get_response(messages=task_message)
            scan_output = scan_response.content
            logger.info("Stage 1/3: Scanner complete")

            # Stage 2: Intelligence
            logger.info("Stage 2/3: Intelligence agent starting")
            intel_prompt = (
                f"Analyze and prioritize the following security scan results. "
                f"The scan was performed on PR #{pr_number} in repository {repo} "
                f"(commit {head_sha}).\n\n"
                f"Scanner output:\n{scan_output}"
            )
            intel_response = await intelligence.get_response(messages=intel_prompt)
            intel_output = intel_response.content
            logger.info("Stage 2/3: Intelligence complete")

            # Stage 3: Remediation — include full PR context so the agent can
            # call GitHub API functions (create_review, post_comment, etc.)
            logger.info("Stage 3/3: Remediation agent starting")
            remediation_prompt = (
                f"## PR Context\n"
                f"- Repository: {repo}\n"
                f"- PR Number: {pr_number}\n"
                f"- Commit SHA: {head_sha}\n\n"
                f"Generate fixes for the following prioritized security findings. "
                f"Post inline suggestions to the PR using the repository, PR number, "
                f"and commit SHA above.\n\n"
                f"Prioritized findings:\n{intel_output}"
            )
            fix_response = await remediation.get_response(messages=remediation_prompt)
            fix_output = fix_response.content
            logger.info("Stage 3/3: Remediation complete")

            result = self._parse_final_response(fix_output)
            result["_raw_stages"] = {
                "scanner": scan_output,
                "intelligence": intel_output,
                "remediation": fix_output,
            }
            return result
        finally:
            await github_plugin.aclose()

    def _build_task_message(self, repo: str, pr_number: int, head_sha: str) -> str:
        """Build the initial task message for the pipeline.

        The PR Context block is structured so agents can extract and
        preserve it through sequential orchestration.
        """
        return (
            f"## PR Context\n"
            f"- Repository: {repo}\n"
            f"- PR Number: {pr_number}\n"
            f"- Commit SHA: {head_sha}\n\n"
            f"Perform a complete security review of the pull request above.\n\n"
            f"Step 1 (Scanner): Analyze all changed files for security vulnerabilities.\n"
            f"Step 2 (Intelligence): Prioritize findings by risk, filter noise, "
            f"enrich with team patterns.\n"
            f"Step 3 (Remediation): Generate validated fixes, assess confidence, "
            f"post inline suggestions to the PR, and escalate uncertain fixes.\n\n"
            f"IMPORTANT: Always include the PR Context block (Repository, PR Number, "
            f"Commit SHA) in your output so downstream agents can use it.\n\n"
            f"Use the PR Review API to post inline code suggestions with "
            f"```suggestion blocks so developers can click 'Commit suggestion'."
        )

    def _parse_final_response(self, output: str) -> dict:
        """Attempt to parse the final agent response as JSON.

        The Remediation Agent should return structured JSON, but LLMs
        sometimes wrap it in markdown code blocks or add commentary.
        We try all code blocks (preferring the last valid one, since
        LLMs typically place the final answer at the end).
        """
        # Try direct JSON parse first
        try:
            return json.loads(output)
        except (json.JSONDecodeError, TypeError):
            pass

        # Extract all fenced code blocks and try each (last-first)
        blocks = re.findall(r"```(?:json)?\s*\n(.*?)\n\s*```", output, re.DOTALL)
        for block in reversed(blocks):
            try:
                return json.loads(block.strip())
            except (json.JSONDecodeError, TypeError):
                continue

        # Fallback: return raw output wrapped in a dict
        logger.warning("Could not parse orchestrator output as JSON")
        return {
            "raw_output": output,
            "parse_error": True,
        }
