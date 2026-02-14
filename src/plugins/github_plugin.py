"""Semantic Kernel plugin for GitHub PR interactions.

Provides read operations (diff, file content, PR metadata) and write
operations (comments, reviews with inline suggestions) via the GitHub REST API.
Uses the PR Review API (not Issues API) for inline code suggestions.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Annotated

import httpx
from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.github")

_GITHUB_API = "https://api.github.com"


class GitHubPlugin:
    """Kernel plugin for reading and writing to GitHub pull requests.

    Creates a shared httpx.AsyncClient for connection pooling across calls.
    Call `aclose()` when done, or use as an async context manager.
    """

    def __init__(self, token: str, timeout: float = 15.0):
        self._client = httpx.AsyncClient(
            base_url=_GITHUB_API,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=timeout,
        )

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with error handling and rate-limit awareness."""
        resp = await self._client.request(
            method, url, headers=headers, json=json_body, params=params,
        )

        # Log rate limit warnings
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining and int(remaining) < 100:
            logger.warning("GitHub API rate limit low: %s requests remaining", remaining)

        resp.raise_for_status()
        return resp

    # --- Read operations ---

    @kernel_function(description="Get pull request metadata including head SHA, base branch, and state")
    async def get_pr_metadata(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
    ) -> Annotated[str, "JSON object with head_sha, head_ref, base_ref, state, title"]:
        try:
            resp = await self._request("GET", f"/repos/{repo}/pulls/{pr_number}")
            data = resp.json()
            return json.dumps({
                "head_sha": data["head"]["sha"],
                "head_ref": data["head"]["ref"],
                "base_ref": data["base"]["ref"],
                "state": data["state"],
                "title": data.get("title", ""),
                "changed_files": data.get("changed_files", 0),
            })
        except httpx.HTTPStatusError as e:
            return json.dumps({"error": f"GitHub API error {e.response.status_code}", "details": e.response.text[:300]})
        except httpx.RequestError as e:
            return json.dumps({"error": f"Network error: {e}"})

    @kernel_function(description="Get the unified diff content for a pull request")
    async def get_pr_diff(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
    ) -> Annotated[str, "Unified diff content of the pull request"]:
        try:
            resp = await self._request(
                "GET",
                f"/repos/{repo}/pulls/{pr_number}",
                headers={"Accept": "application/vnd.github.v3.diff"},
            )
            return resp.text
        except httpx.HTTPStatusError as e:
            return f"[Error fetching PR diff: HTTP {e.response.status_code}]"
        except httpx.RequestError as e:
            return f"[Network error fetching PR diff: {e}]"

    @kernel_function(description="Get the list of files changed in a pull request")
    async def get_pr_files(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
    ) -> Annotated[str, "JSON array of changed files with filename, status, and patch"]:
        try:
            resp = await self._request("GET", f"/repos/{repo}/pulls/{pr_number}/files")
            files = [
                {
                    "filename": f["filename"],
                    "status": f["status"],
                    "additions": f["additions"],
                    "deletions": f["deletions"],
                    "patch": f.get("patch", ""),
                }
                for f in resp.json()
            ]
            return json.dumps(files)
        except httpx.HTTPStatusError as e:
            return json.dumps({"error": f"GitHub API error {e.response.status_code}", "files": []})
        except httpx.RequestError as e:
            return json.dumps({"error": f"Network error: {e}", "files": []})

    @kernel_function(description="Get content of a specific file at a given git ref")
    async def get_file_content(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        path: Annotated[str, "File path within repository"],
        ref: Annotated[str, "Git ref (branch, tag, or SHA)"],
    ) -> Annotated[str, "File content as text, or error message for binary files"]:
        try:
            resp = await self._request(
                "GET",
                f"/repos/{repo}/contents/{path}",
                params={"ref": ref},
            )
            data = resp.json()

            encoding = data.get("encoding", "base64")
            if encoding != "base64":
                return f"[Unsupported encoding '{encoding}' for file: {path}]"

            raw = base64.b64decode(data.get("content", ""))
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return f"[Binary file: {path} — cannot display content]"

        except httpx.HTTPStatusError as e:
            return f"[Error fetching {path}: HTTP {e.response.status_code}]"
        except httpx.RequestError as e:
            return f"[Network error fetching {path}: {e}]"

    # --- Write operations ---

    @kernel_function(description="Post a summary comment on a pull request")
    async def post_summary_comment(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
        body: Annotated[str, "Comment body in GitHub-flavored markdown"],
    ) -> Annotated[str, "URL of the created comment"]:
        try:
            resp = await self._request(
                "POST",
                f"/repos/{repo}/issues/{pr_number}/comments",
                json_body={"body": body},
            )
            return resp.json().get("html_url", "comment posted")
        except httpx.HTTPStatusError as e:
            logger.error("Failed to post comment on PR #%d: HTTP %d", pr_number, e.response.status_code)
            return f"[Error posting comment: HTTP {e.response.status_code}]"
        except httpx.RequestError as e:
            logger.error("Network error posting comment on PR #%d: %s", pr_number, e)
            return f"[Network error posting comment: {e}]"

    @kernel_function(description="Post a PR review with inline code suggestions on specific diff lines")
    async def create_review_with_suggestions(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
        commit_sha: Annotated[str, "SHA of the commit to review"],
        suggestions_json: Annotated[
            str,
            "JSON array of objects with: path, start_line, end_line, fixed_code, explanation, severity, confidence",
        ],
    ) -> Annotated[str, "URL of the created review"]:
        """Post inline code suggestions using GitHub's PR Review API.

        Each suggestion uses the ```suggestion markdown block so developers
        can click 'Commit suggestion' directly in the PR UI.
        """
        try:
            suggestions = json.loads(suggestions_json)
        except json.JSONDecodeError as e:
            return f"[Error: invalid suggestions JSON — {e}]"

        if not isinstance(suggestions, list):
            return "[Error: suggestions_json must be a JSON array]"

        comments = []
        for s in suggestions:
            confidence = s.get("confidence", 0)
            severity = s.get("severity", "MEDIUM")

            # Build the suggestion body with confidence badge
            if confidence >= 0.9:
                badge = ":white_check_mark: **[Auto-Applicable]**"
            elif confidence >= 0.7:
                badge = ":warning: **[Review Required]**"
            else:
                badge = ":rotating_light: **[Needs Expert Review]**"

            body = f"{badge} | **{severity}** | Confidence: {confidence:.0%}\n\n"
            body += f"{s.get('explanation', '')}\n\n"
            body += f"```suggestion\n{s['fixed_code']}\n```"

            comment: dict = {
                "path": s["path"],
                "body": body,
                "line": s["end_line"],
            }
            # Multi-line suggestions require start_line
            if s.get("start_line") and s["start_line"] != s["end_line"]:
                comment["start_line"] = s["start_line"]

            comments.append(comment)

        try:
            resp = await self._request(
                "POST",
                f"/repos/{repo}/pulls/{pr_number}/reviews",
                json_body={
                    "commit_id": commit_sha,
                    "event": "COMMENT",
                    "comments": comments,
                },
            )
            return resp.json().get("html_url", "review posted")
        except httpx.HTTPStatusError as e:
            logger.error("Failed to post review on PR #%d: HTTP %d", pr_number, e.response.status_code)
            return f"[Error posting review: HTTP {e.response.status_code} — {e.response.text[:200]}]"
        except httpx.RequestError as e:
            return f"[Network error posting review: {e}]"

    @kernel_function(description="Add a label to a pull request")
    async def add_label(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        pr_number: Annotated[int, "Pull request number"],
        label: Annotated[str, "Label name to add (e.g. security-review-needed)"],
    ) -> Annotated[str, "Confirmation that label was added"]:
        try:
            await self._request(
                "POST",
                f"/repos/{repo}/issues/{pr_number}/labels",
                json_body={"labels": [label]},
            )
            return f"Label '{label}' added to PR #{pr_number}"
        except httpx.HTTPStatusError as e:
            return f"[Error adding label: HTTP {e.response.status_code}]"
        except httpx.RequestError as e:
            return f"[Network error adding label: {e}]"

    @kernel_function(description="Create a GitHub issue for security escalation")
    async def create_escalation_issue(
        self,
        repo: Annotated[str, "Repository in owner/name format"],
        title: Annotated[str, "Issue title"],
        body: Annotated[str, "Issue body in markdown"],
        pr_number: Annotated[int, "Related PR number for cross-reference"],
    ) -> Annotated[str, "URL of the created issue"]:
        issue_body = f"{body}\n\n---\n_Related to PR #{pr_number}_"
        try:
            resp = await self._request(
                "POST",
                f"/repos/{repo}/issues",
                json_body={
                    "title": title,
                    "body": issue_body,
                    "labels": ["security-escalation"],
                },
            )
            return resp.json().get("html_url", "issue created")
        except httpx.HTTPStatusError as e:
            return f"[Error creating issue: HTTP {e.response.status_code}]"
        except httpx.RequestError as e:
            return f"[Network error creating issue: {e}]"
