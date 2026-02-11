# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Nature

This is a **design-only repository** for a hackathon project — there is no runnable code, build system, or tests. The repo contains planning and concept documents for a DevSecOps Intelligence Platform: an AI-powered multi-agent security system for development workflows.

## Document Map

- `idea.md` — The primary, comprehensive design document. Contains the full problem statement, real-world scenario walkthrough, detailed agent architectures with Python pseudocode, Azure infrastructure specs, implementation roadmap (5 weeks), risk analysis, and differentiation strategy. **Read this first** for any technical question.
- `revised_idea.md` — Addresses gaps identified in `idea.md`: adds technical depth (specific Azure services, data strategy, AI/ML integration), mitigates risks (agent failure handling, hallucination prevention), and refines the implementation roadmap with Azure-specific tooling per week.
- `innovation_summary.md` — Executive summary / pitch document. Condensed version of key innovations and competitive advantages, suitable for presentation or quick stakeholder review.

## Key Concepts

**Five-agent architecture** (Microsoft Agent Framework + Semantic Kernel):
1. Detection (Scanner) — SAST/dependency/secrets scanning via Semgrep, Trivy
2. Contextualization — Team pattern recognition using knowledge graph (Cosmos DB Gremlin API)
3. Prioritization — Multi-factor risk scoring (reachability, business impact, exploit complexity)
4. Remediation — Context-aware fix generation with validation and confidence thresholds
5. Integration — GitHub/Azure ecosystem connectivity via MCP servers

**Tech stack**: Azure Container Apps, Cosmos DB, Azure OpenAI via Microsoft Foundry, Azure ML, Azure AI Search, Semantic Kernel orchestration.

**MVP scope** (3-agent simplified version): Scanner + Intelligence (context+priority combined) + Remediation.

## Working in This Repo

When asked to develop features or write code for this project, reference the pseudocode patterns in `idea.md` (agent class structures, orchestration workflow, observability patterns) as the canonical style guide. The codebase targets Python with async patterns, OpenTelemetry instrumentation, and Azure SDK integrations.

The confidence-based fix pipeline is a core design decision:
- \>90% confidence → auto-apply
- 70-90% → human review
- <70% → escalate to security team
