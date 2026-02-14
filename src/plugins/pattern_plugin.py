"""Semantic Kernel plugin for the knowledge base of fix patterns.

Provides team-specific historical fix patterns from Cosmos DB,
enabling the Intelligence Agent to recommend contextual fixes.
Also supports a learning loop: when fixes are accepted or rejected,
pattern confidence is updated so the system improves over time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Annotated

from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.patterns")


class PatternPlugin:
    """Kernel plugin for querying and updating fix patterns in Cosmos DB."""

    def __init__(self, cosmos_client, database_name: str):
        db = cosmos_client.get_database_client(database_name)
        self._container = db.get_container_client("patterns")

    @kernel_function(
        description="Query historical fix patterns for a vulnerability type, returning team-preferred remediation approaches sorted by confidence"
    )
    async def get_team_patterns(
        self,
        vuln_type: Annotated[str, "Vulnerability type (e.g. sql_injection, xss, hardcoded_secret)"],
        language: Annotated[str, "Programming language"],
        repo: Annotated[str, "Repository name (optional, for repo-specific patterns)"] = "",
    ) -> Annotated[str, "JSON array of fix patterns sorted by confidence"]:
        query = (
            "SELECT c.vuln_type, c.fix_pattern, c.language, c.framework, "
            "c.confidence, c.accepted_count, c.rejected_count "
            "FROM c WHERE c.vuln_type = @vuln_type AND c.language = @language "
            "ORDER BY c.confidence DESC, c.accepted_count DESC "
            "OFFSET 0 LIMIT 5"
        )
        params: list[dict] = [
            {"name": "@vuln_type", "value": vuln_type},
            {"name": "@language", "value": language},
        ]

        try:
            patterns = [
                item async for item in self._container.query_items(
                    query=query, parameters=params,
                )
            ]
        except asyncio.CancelledError:
            logger.warning("Pattern query cancelled (agent timeout)")
            raise
        except Exception as e:
            logger.warning("Cosmos DB pattern query failed: %s", e)
            return json.dumps({"patterns": [], "error": str(e)})

        if not patterns:
            return json.dumps({
                "patterns": [],
                "message": f"No patterns found for {vuln_type} in {language}",
            })

        return json.dumps({"patterns": patterns, "count": len(patterns)})

    @kernel_function(
        description="Get the single best fix pattern for a vulnerability type and language, preferring repo-specific patterns"
    )
    async def get_best_fix_pattern(
        self,
        vuln_type: Annotated[str, "Vulnerability type (e.g. sql_injection, xss)"],
        language: Annotated[str, "Programming language"],
        repo: Annotated[str, "Repository full name (e.g. owner/repo)"] = "",
    ) -> Annotated[str, "JSON with the best fix pattern or null"]:
        """Return the highest-confidence pattern, preferring repo-specific ones."""
        # Try repo-specific pattern first
        if repo:
            query = (
                "SELECT TOP 1 c.id, c.vuln_type, c.fix_pattern, c.language, "
                "c.framework, c.confidence, c.accepted_count, c.rejected_count "
                "FROM c WHERE c.vuln_type = @vuln_type AND c.language = @language "
                "AND c.repo = @repo "
                "ORDER BY c.confidence DESC"
            )
            params = [
                {"name": "@vuln_type", "value": vuln_type},
                {"name": "@language", "value": language},
                {"name": "@repo", "value": repo},
            ]
            try:
                results = [
                    item async for item in self._container.query_items(
                        query=query, parameters=params,
                    )
                ]
                if results:
                    return json.dumps({"pattern": results[0], "source": "repo-specific"})
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("Repo-specific pattern query failed: %s", e)

        # Fallback to global pattern
        query = (
            "SELECT TOP 1 c.id, c.vuln_type, c.fix_pattern, c.language, "
            "c.framework, c.confidence, c.accepted_count, c.rejected_count "
            "FROM c WHERE c.vuln_type = @vuln_type AND c.language = @language "
            "ORDER BY c.confidence DESC, c.accepted_count DESC"
        )
        params = [
            {"name": "@vuln_type", "value": vuln_type},
            {"name": "@language", "value": language},
        ]
        try:
            results = [
                item async for item in self._container.query_items(
                    query=query, parameters=params,
                )
            ]
            if results:
                return json.dumps({"pattern": results[0], "source": "global"})
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Global pattern query failed: %s", e)

        return json.dumps({"pattern": None, "message": "No pattern found"})

    @kernel_function(
        description="Record the outcome of a fix suggestion (accepted or rejected) to update pattern confidence over time"
    )
    async def store_fix_outcome(
        self,
        vuln_type: Annotated[str, "Vulnerability type"],
        fix_pattern: Annotated[str, "Description of the fix pattern used"],
        language: Annotated[str, "Programming language"],
        accepted: Annotated[bool, "True if the fix was merged, False if rejected"],
        repo: Annotated[str, "Repository full name"] = "",
        framework: Annotated[str, "Framework used (e.g. SQLAlchemy, Express)"] = "",
    ) -> Annotated[str, "JSON confirming the outcome was recorded"]:
        """Upsert a pattern document: increment accepted/rejected count and recalculate confidence."""
        # Build a deterministic ID so we upsert the same doc for the same pattern
        pattern_id = f"{vuln_type}:{language}:{framework or 'generic'}".lower()
        if repo:
            pattern_id += f":{repo}"

        max_retries = 3
        try:
            # Try to read existing document
            try:
                existing = await self._container.read_item(
                    item=pattern_id, partition_key=vuln_type,
                )
            except Exception:
                existing = None

            if existing:
                # Update with optimistic concurrency (retry on ETag conflict)
                for attempt in range(max_retries):
                    if accepted:
                        existing["accepted_count"] = existing.get("accepted_count", 0) + 1
                    else:
                        existing["rejected_count"] = existing.get("rejected_count", 0) + 1
                    total = existing["accepted_count"] + existing["rejected_count"]
                    existing["confidence"] = round(existing["accepted_count"] / total, 3) if total > 0 else 0.5
                    try:
                        await self._container.replace_item(
                            item=pattern_id,
                            body=existing,
                            etag=existing.get("_etag", ""),
                            match_condition="IfMatch",
                        )
                        break
                    except Exception as conflict_err:
                        if attempt < max_retries - 1 and "412" in str(conflict_err):
                            logger.warning("Concurrent update on pattern %s, retrying", pattern_id)
                            # Re-read the document to get fresh ETag + counts
                            existing = await self._container.read_item(
                                item=pattern_id, partition_key=vuln_type,
                            )
                            continue
                        # Last retry or non-conflict error — fall back to upsert
                        await self._container.upsert_item(existing)
                        break
                action = "updated"
            else:
                doc = {
                    "id": pattern_id,
                    "vuln_type": vuln_type,
                    "fix_pattern": fix_pattern,
                    "language": language,
                    "framework": framework,
                    "repo": repo,
                    "accepted_count": 1 if accepted else 0,
                    "rejected_count": 0 if accepted else 1,
                    "confidence": 1.0 if accepted else 0.0,
                }
                await self._container.upsert_item(doc)
                action = "created"

            logger.info(
                "Pattern %s %s (accepted=%s, confidence=%.2f)",
                pattern_id, action, accepted,
                existing["confidence"] if existing else (1.0 if accepted else 0.0),
            )
            return json.dumps({"status": "ok", "action": action, "pattern_id": pattern_id})

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("Failed to store fix outcome: %s", e)
            return json.dumps({"status": "error", "error": str(e)})

    @kernel_function(
        description="Detect frameworks and libraries used in a repository based on filenames"
    )
    async def get_framework_info(
        self,
        file_list_json: Annotated[str, "JSON array of filenames in the repository"],
    ) -> Annotated[str, "JSON object describing detected frameworks, ORMs, and test frameworks"]:
        """Infer frameworks from filenames — lightweight, no API calls needed."""
        try:
            files = json.loads(file_list_json)
        except (json.JSONDecodeError, TypeError):
            files = []

        file_set = {str(f).lower() for f in files}
        detected: dict[str, list[str]] = {
            "frameworks": [],
            "orms": [],
            "test_frameworks": [],
        }

        # Python signals
        if any(f.endswith("requirements.txt") or f == "pyproject.toml" for f in file_set):
            # Could be any Python framework — check imports in future
            detected["frameworks"].append("Python")
        if any("django" in f for f in file_set):
            detected["frameworks"].append("Django")
        if any("flask" in f or "wsgi" in f for f in file_set):
            detected["frameworks"].append("Flask")
        if any("fastapi" in f or "uvicorn" in f for f in file_set):
            detected["frameworks"].append("FastAPI")

        # JavaScript/TypeScript signals
        if "package.json" in file_set:
            detected["frameworks"].append("Node.js")
        if any("next.config" in f for f in file_set):
            detected["frameworks"].append("Next.js")

        # ORMs
        if any("prisma" in f for f in file_set):
            detected["orms"].append("Prisma")
        if any("alembic" in f for f in file_set):
            detected["orms"].append("SQLAlchemy")
        if any("sequelize" in f for f in file_set):
            detected["orms"].append("Sequelize")

        # Test frameworks
        if any("pytest" in f or "conftest" in f for f in file_set):
            detected["test_frameworks"].append("pytest")
        if any("jest" in f for f in file_set):
            detected["test_frameworks"].append("Jest")

        return json.dumps(detected)
