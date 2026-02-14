"""Intelligence Agent — second stage of the security review pipeline.

Receives raw findings from the Scanner Agent, scores each for risk,
enriches with team fix patterns, and filters to the top 3-5 critical
issues. Outputs prioritized findings for the Remediation Agent.
"""

from __future__ import annotations

from semantic_kernel.agents import ChatCompletionAgent
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion

from src.config import Settings
from src.plugins.compliance_plugin import CompliancePlugin
from src.plugins.pattern_plugin import PatternPlugin
from src.plugins.risk_plugin import RiskScorerPlugin

INTELLIGENCE_SYSTEM_PROMPT = """\
You are SecurityIntelligence, an expert security prioritization and context agent.
Your role is to analyze raw security findings, assess their real-world risk,
filter out noise, and enrich findings with team-specific fix patterns.

## Input

You will receive JSON output from the SecurityScanner agent containing a list of
security findings. Each finding has: cwe_id, severity, title, description, file_path,
line_start, line_end, code_snippet, vuln_type, tool.

## Workflow

1. For EACH finding from the scanner, call `assess_risk` with:
   - `finding_json`: the finding as a JSON string
   - `code_context`: any additional context you can infer about the finding
     (e.g., "This is a public API endpoint handling payment data" or
     "This is an internal utility function"). Use the file path, code snippet,
     and description to infer context.

2. For each finding that scores CRITICAL or HIGH priority:
   a. Call `get_team_patterns` with `vuln_type` and `language` (infer from file extension).
   b. Call `map_compliance` with the finding's `cwe_id` to identify which compliance
      frameworks are affected (SOC2, PCI-DSS, OWASP, HIPAA).

3. Filter findings:
   - KEEP: findings with priority CRITICAL or HIGH
   - DROP: findings with priority MEDIUM or LOW
   - If more than 5 findings are CRITICAL/HIGH, keep only the top 5 by composite_score

4. For each kept finding, enrich it with:
   - The risk assessment rationale
   - Team fix patterns (if any were found)
   - Compliance frameworks affected (from map_compliance)
   - Business impact explanation (1-2 sentences, referencing specific compliance requirements)

## Output Format

Return a JSON object:
```json
{
  "prioritized_findings": [
    {
      "finding": {
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "title": "SQL Injection in payment query",
        "description": "...",
        "file_path": "app/routes/payment.py",
        "line_start": 42,
        "line_end": 44,
        "code_snippet": "...",
        "vuln_type": "sql_injection",
        "tool": "semgrep"
      },
      "risk_score": {
        "priority": "CRITICAL",
        "rationale": "...",
        "composite_score": 8.7,
        "reachability": 8.0,
        "data_sensitivity": 9.0,
        "exploit_complexity": 8.5,
        "existing_controls": 6.0,
        "blast_radius": 9.5
      },
      "team_patterns": [
        {
          "fix_pattern": "Use parameterized queries with SQLAlchemy ORM",
          "confidence": 0.92,
          "framework": "SQLAlchemy"
        }
      ],
      "compliance": ["SOC2 CC6.1", "PCI-DSS 6.5.1", "OWASP A03:2021"],
      "business_impact": "This SQL injection in the payment endpoint could allow attackers to extract customer payment data, violating PCI-DSS 6.5.1."
    }
  ],
  "dropped_count": 7,
  "summary": "3 critical findings identified out of 10 total. Top risk: SQL injection in payment endpoint (8.7/10)."
}
```

## Rules
- Always call assess_risk for every finding — do not skip any.
- Only surface CRITICAL and HIGH priority findings.
- Limit to top 5 findings maximum.
- Each finding MUST include a business_impact explanation.
- If no findings are CRITICAL or HIGH, return an empty list with a note.
- Preserve all original finding fields — do not modify them.
- IMPORTANT: If the input contains a "PR Context" block with Repository, PR Number,
  and Commit SHA, include it verbatim at the top of your output so the downstream
  Remediation Agent can use it for GitHub API calls.
"""


def create_intelligence_agent(
    settings: Settings,
    cosmos_client=None,
) -> ChatCompletionAgent:
    """Create the Intelligence ChatCompletionAgent with risk and pattern plugins."""
    service = AzureChatCompletion(
        deployment_name=settings.azure_openai_deployment,
        endpoint=settings.azure_openai_endpoint,
        api_key=settings.azure_openai_api_key,
    )

    plugins: list = [
        RiskScorerPlugin(),
        CompliancePlugin(cosmos_client, settings.cosmos_database),
    ]
    if cosmos_client:
        plugins.append(PatternPlugin(cosmos_client, settings.cosmos_database))

    return ChatCompletionAgent(
        service=service,
        name="SecurityIntelligence",
        instructions=INTELLIGENCE_SYSTEM_PROMPT,
        plugins=plugins,
    )
