"""MCP (Model Context Protocol) integration for SecureFlow AI.

Wraps the official GitHub MCP server as a Semantic Kernel plugin
using MCPStdioPlugin. This provides agents with broad GitHub
capabilities (search, issues, repos) alongside our custom
GitHubPlugin which handles specialized PR Review API calls.

The MCP server runs as a subprocess managed by SK's MCP runtime.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from semantic_kernel.connectors.mcp import MCPStdioPlugin

logger = logging.getLogger("secureflow.mcp")

# MCP server command and arguments
_GITHUB_MCP_CMD = "npx"
_GITHUB_MCP_ARGS = ["-y", "@modelcontextprotocol/server-github"]


async def create_github_mcp_plugin(github_token: str) -> MCPStdioPlugin:
    """Create and connect to the GitHub MCP server.

    The MCP server provides these capabilities (among others):
    - search_repositories, search_code, search_issues
    - get_file_contents, list_commits
    - create_issue, create_pull_request
    - list_issues, get_issue

    Our custom GitHubPlugin handles the specialized calls:
    - create_review_with_suggestions (PR Review API with ```suggestion blocks)
    - post_summary_comment
    - get_pr_diff, get_pr_files, get_pr_metadata

    Together, they give agents full GitHub coverage.

    Returns:
        An MCPStdioPlugin instance connected to the GitHub MCP server.
        Caller must call `await plugin.close()` when done.
    """
    from semantic_kernel.connectors.mcp import MCPStdioPlugin

    plugin = MCPStdioPlugin(
        name="GitHubMCP",
        command=_GITHUB_MCP_CMD,
        args=_GITHUB_MCP_ARGS,
        env={"GITHUB_PERSONAL_ACCESS_TOKEN": github_token},
    )
    await plugin.connect()
    logger.info("GitHub MCP server connected (tools available via MCPStdioPlugin)")
    return plugin


async def close_mcp_plugin(plugin: MCPStdioPlugin) -> None:
    """Safely close an MCP plugin, stopping the subprocess."""
    try:
        await plugin.close()
        logger.info("GitHub MCP server disconnected")
    except Exception as e:
        logger.warning("Error closing MCP plugin: %s", e)
