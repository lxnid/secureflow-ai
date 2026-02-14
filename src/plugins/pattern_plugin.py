"""Semantic Kernel plugin for querying the knowledge base of fix patterns.

Provides team-specific historical fix patterns from Cosmos DB,
enabling the Intelligence Agent to recommend contextual fixes.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated

from semantic_kernel.functions import kernel_function

logger = logging.getLogger("secureflow.patterns")


class PatternPlugin:
    """Kernel plugin for querying historical fix patterns in Cosmos DB."""

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
