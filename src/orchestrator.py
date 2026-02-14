"""Multi-agent orchestrator for the security review pipeline.

Wires Scanner → Intelligence → Remediation using Semantic Kernel's
SequentialOrchestration (Option A) with a manual chaining fallback
(Option B) if the experimental orchestration API has issues.

Optionally integrates the GitHub MCP server for broader GitHub
capabilities alongside the custom GitHubPlugin.
"""

from __future__ import annotations

import json
import logging
import re
import time

from opentelemetry import trace

from src.agents.intelligence import create_intelligence_agent
from src.agents.remediation import create_remediation_agent
from src.agents.scanner import create_scanner_agent
from src.config import Settings
from src.plugins.github_plugin import GitHubPlugin
from src.plugins.mcp_plugin import close_mcp_plugin, create_github_mcp_plugin

logger = logging.getLogger("secureflow.orchestrator")


class SecurityReviewOrchestrator:
    """Orchestrates the 3-agent security review pipeline.

    Attempts SequentialOrchestration first (SK experimental API).
    Falls back to manual get_response() chaining if that fails.
    """

    def __init__(self, settings: Settings, cosmos_client=None, use_mcp: bool = True):
        self._settings = settings
        self._cosmos_client = cosmos_client
        self._use_mcp = use_mcp

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
        tracer = trace.get_tracer("secureflow-ai")
        start = time.monotonic()

        with tracer.start_as_current_span("pipeline.analyze_pr") as span:
            span.set_attribute("pr.repo", repo)
            span.set_attribute("pr.number", pr_number)
            span.set_attribute("pr.head_sha", head_sha)

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

            span.set_attribute("pipeline.mode", result["orchestration_mode"])
            span.set_attribute("pipeline.duration_s", result["duration_seconds"])
            span.set_attribute("pipeline.fix_count", len(result.get("fixes", [])))
            span.set_attribute("pipeline.mcp_enabled", result.get("mcp_enabled", False))

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
            remediation = create_remediation_agent(
                self._settings, github_plugin=github_plugin, cosmos_client=self._cosmos_client,
            )

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
        mcp_plugin = None
        try:
            # Try to start GitHub MCP server for supplementary capabilities
            if self._use_mcp:
                try:
                    mcp_plugin = await create_github_mcp_plugin(self._settings.github_token)
                    logger.info("MCP server available — agents have extended GitHub capabilities")
                except Exception as e:
                    logger.warning("MCP server unavailable (%s) — using custom plugin only", e)

            scanner = create_scanner_agent(
                self._settings, github_plugin=github_plugin, mcp_plugin=mcp_plugin,
            )
            intelligence = create_intelligence_agent(self._settings, self._cosmos_client)
            remediation = create_remediation_agent(
                self._settings, github_plugin=github_plugin, cosmos_client=self._cosmos_client,
            )

            tracer = trace.get_tracer("secureflow-ai")
            task_message = self._build_task_message(repo, pr_number, head_sha)

            scan_output = ""
            intel_output = ""
            fix_output = ""
            failed_stage = None

            # Stage 1: Scanner (if this fails, nothing to work with)
            with tracer.start_as_current_span("agent.scanner") as scan_span:
                logger.info("Stage 1/3: Scanner agent starting")
                try:
                    scan_response = await scanner.get_response(messages=task_message)
                    scan_output = scan_response.content
                    scan_span.set_attribute("agent.name", "SecurityScanner")
                    scan_span.set_attribute("output.length", len(scan_output))
                    logger.info("Stage 1/3: Scanner complete")
                except Exception as e:
                    scan_span.set_status(trace.StatusCode.ERROR, str(e))
                    logger.exception("Stage 1/3: Scanner FAILED")
                    raise  # Scanner failure is unrecoverable

            # Stage 2: Intelligence (if this fails, return raw scan results)
            with tracer.start_as_current_span("agent.intelligence") as intel_span:
                logger.info("Stage 2/3: Intelligence agent starting")
                try:
                    intel_prompt = (
                        f"Analyze and prioritize the following security scan results. "
                        f"The scan was performed on PR #{pr_number} in repository {repo} "
                        f"(commit {head_sha}).\n\n"
                        f"Scanner output:\n{scan_output}"
                    )
                    intel_response = await intelligence.get_response(messages=intel_prompt)
                    intel_output = intel_response.content
                    intel_span.set_attribute("agent.name", "SecurityIntelligence")
                    intel_span.set_attribute("output.length", len(intel_output))
                    logger.info("Stage 2/3: Intelligence complete")
                except Exception as e:
                    intel_span.set_status(trace.StatusCode.ERROR, str(e))
                    logger.exception("Stage 2/3: Intelligence FAILED — returning scan results only")
                    failed_stage = "intelligence"

            # Stage 3: Remediation (if this fails, return prioritized findings)
            if not failed_stage:
                with tracer.start_as_current_span("agent.remediation") as fix_span:
                    logger.info("Stage 3/3: Remediation agent starting")
                    try:
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
                        fix_span.set_attribute("agent.name", "SecurityRemediation")
                        fix_span.set_attribute("output.length", len(fix_output))
                        logger.info("Stage 3/3: Remediation complete")
                    except Exception as e:
                        fix_span.set_status(trace.StatusCode.ERROR, str(e))
                        logger.exception("Stage 3/3: Remediation FAILED — returning prioritized findings only")
                        failed_stage = "remediation"

            # Build result based on how far we got (circuit breaker)
            if failed_stage == "intelligence":
                result = {"raw_output": scan_output, "partial": True, "failed_stage": "intelligence"}
            elif failed_stage == "remediation":
                result = self._parse_final_response(intel_output)
                result["partial"] = True
                result["failed_stage"] = "remediation"
            else:
                result = self._parse_final_response(fix_output)

            result["_raw_stages"] = {
                "scanner": scan_output,
                "intelligence": intel_output,
                "remediation": fix_output,
            }
            result["mcp_enabled"] = mcp_plugin is not None
            return result
        finally:
            await github_plugin.aclose()
            if mcp_plugin is not None:
                await close_mcp_plugin(mcp_plugin)

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
