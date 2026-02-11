# SecureFlow AI - Revised Development Plan

## Context

The hackathon is Microsoft AI Dev Days with a **4-week deadline** and **5 judging criteria at 20% each**: Technological Implementation, Agentic Design & Innovation, Real-World Impact, User Experience & Presentation, and Adherence to Hackathon Category.

**Target category:** Best Overall Agent ($20K) — must score well across ALL 5 criteria

**Team size:** Solo developer — all work is sequential, scope must be realistic

Past winners (RiskWise, Apollo, TARIFFED!, Konveyor) all used **Semantic Kernel + Azure AI Agent Service** with proper multi-agent orchestration, data grounding, and polished demos.

---

## Part 1: Critique of the Suggested Plan

### Fatal Flaws

**1. No actual agentic design (kills 20% of score)**
The plan builds a plain FastAPI app with sequential function calls. There is zero Semantic Kernel usage, zero Agent Framework integration, zero multi-agent orchestration. The "agent" is just `analyze_pr()` calling `scanner.scan_code()` then `ai_client.generate_fix()`. This is a script, not an agent system. Judges scoring "Agentic Design & Innovation" would give this near-zero marks.

**2. Missing every hero technology (kills another 20%)**
"Adherence to Hackathon Category" requires genuine use of promoted technologies. The plan uses none:
- No Semantic Kernel (despite being THE framework judges look for)
- No Azure AI Agent Service (the featured deployment target)
- No MCP servers (the promoted integration standard)
- No agent orchestration patterns (sequential, handoff, group chat)

Past winners ALL used Semantic Kernel + Azure AI Agent Service. This plan would be immediately disqualified from "Best Azure AI Agent Service Usage" and "Best Agent in Python" categories.

**3. Timeline mismatch — plan is 5 weeks, deadline is 4**
The plan allocates Week 5 for polish/demo, but we only have 4 weeks total.

**4. Week 4 wasted on a Flask dashboard**
An entire week building a Flask+Chart.js dashboard from scratch. The UX judges care about is the **GitHub PR experience** — the comments, suggestions, and developer workflow. A dashboard can be done in 2-3 hours with Streamlit, not 10-12 hours with Flask.

**5. Core design decisions from design docs are missing**
The confidence-based pipeline (>90% auto-apply, 70-90% review, <70% escalate) — the most interesting architectural feature — is completely absent. The compliance evidence generation — a key differentiator — is dropped. The knowledge graph for team patterns is mentioned but never implemented.

### Significant Problems

**6. Semgrep via subprocess is fragile**
Running `subprocess.run(["semgrep", ...])` in a container is brittle. It requires installing Semgrep in the Docker image, handling timeouts manually, and parsing JSON output. A proper approach wraps this as a Semantic Kernel plugin/tool that agents can invoke.

**7. Security vulnerability in the plan itself**
`COPY .env .env` in the Dockerfile copies secrets into the image layer. Anyone who pulls the image gets all credentials. Secrets must be injected via environment variables or Azure Key Vault.

**8. GitHub suggestions format is wrong**
The plan uses ` ```suggestion ` markdown blocks in issue comments, but GitHub's suggestion feature only works in **PR review comments on specific diff lines** via the Pull Request Review API — not the Issues API the plan uses.

**9. No real data grounding**
Cosmos DB is set up but barely used. Winners like TARIFFED! grounded agents in structured domain data. The knowledge graph for team patterns (the key differentiator from design docs) is never built.

**10. No testing aligned with judging**
Tests verify individual functions (`test_scanner.py`, `test_ai_client.py`) but never test the agentic behavior — multi-agent orchestration, confidence routing, tool selection. Judges want to see the agent system work end-to-end.

### Inefficiencies

**11. Excessive hand-holding wastes cognitive bandwidth**
~60% of the plan is tutorial content (how to install Python, create a GitHub account, install VS Code extensions). A hackathon team needs a build plan, not a learning guide.

**12. Over-engineered deployment, under-engineered agent**
The plan spends hours on Docker, ACR, Container Apps deployment but the "agent" is just a FastAPI endpoint. The ratio is inverted — deployment should be simple (Foundry Agent Service handles it), agent design should be sophisticated.

**13. No parallel development strategy**
Everything is sequential. A 2-3 person team could parallelize: one person on agent orchestration, one on tools/scanning, one on GitHub integration + UX.

---

## Part 2: Our Plan

### Strategy

**Core insight from past winners:** Judges reward *genuine multi-agent orchestration with data grounding and responsible AI features*. Not fancy UIs or complex deployments — **the agent architecture IS the product**.

**Architecture:** 3-agent MVP using Semantic Kernel's multi-agent orchestration with proper plugins, MCP integration, and the confidence-based pipeline from our design docs.

**Solo scope adjustments:**
- Knowledge graph: Use Cosmos DB NoSQL (simpler) instead of Gremlin API (complex graph queries are time-sink)
- Dashboard: Streamlit with ~2 hours effort, not a polished app
- Foundry Agent Service: Keep as stretch goal; Container Apps deployment is sufficient if time runs short
- Focus effort on: agent orchestration quality > number of features

### Technology Choices

| Component | Technology | Why |
|-----------|-----------|-----|
| Agent Framework | Semantic Kernel Python (v1.39+) | Stable, judges expect it, full multi-agent orchestration |
| Agent Hosting | Azure AI Foundry Agent Service | Hero technology, simplifies deployment, built-in state management |
| Orchestration | Sequential + Handoff patterns | Scanner→Intelligence→Remediation pipeline with confidence-based routing |
| LLM | Azure OpenAI (GPT-4o) | Via Foundry, required by hackathon |
| Tools | Semantic Kernel Plugins + MCP | Semgrep, Trivy, GitHub as SK plugins; GitHub MCP for integration |
| Data | Cosmos DB (NoSQL + Gremlin API) | Findings cache + knowledge graph for team patterns |
| Vector Search | Azure AI Search | Semantic similarity for pattern matching |
| Observability | OpenTelemetry + Application Insights | Built into Foundry Agent Service |
| Dashboard | Streamlit (minimal) | Quick, Python-native, good enough for demo |
| GitHub UX | PR Review API (not Issues API) | Proper inline suggestions on diff lines |

### Agent Architecture

```
GitHub PR Webhook
       │
       ▼
┌─────────────────────────────────┐
│  Orchestrator (Semantic Kernel) │
│  SecurityReviewWorkflow         │
│  - Sequential orchestration     │
│  - Shared state (Cosmos DB)     │
│  - Confidence-based routing     │
└───────┬─────────┬───────────────┘
        │         │         │
        ▼         ▼         ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│ Scanner  │ │ Intel    │ │ Remediation  │
│ Agent    │ │ Agent    │ │ Agent        │
│          │ │          │ │              │
│ Plugins: │ │ Plugins: │ │ Plugins:     │
│ -Semgrep │ │ -Pattern │ │ -FixGen      │
│ -Trivy   │ │  Match   │ │ -Validator   │
│ -GitDiff │ │ -Risk    │ │ -GitHub      │
│          │ │  Score   │ │  Suggest     │
└──────────┘ └──────────┘ └──────────────┘
```

**Confidence-based routing (core design decision):**
- >90% confidence → Agent auto-applies suggestion via PR review
- 70-90% → Posts as suggestion with "[Review Required]" label
- <70% → Creates separate issue, tags security team

---

### Validated Semantic Kernel API Patterns

All architecture choices have been validated against Semantic Kernel Python v1.39+ docs:

```python
# Core imports for the entire project
from semantic_kernel.agents import ChatCompletionAgent, SequentialOrchestration
from semantic_kernel.agents.runtime import InProcessRuntime
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
from semantic_kernel.connectors.mcp import MCPStdioPlugin, MCPSsePlugin
from semantic_kernel.functions import kernel_function
from typing import Annotated
```

**Agent creation** — each agent is a `ChatCompletionAgent` (GA since v1.27):
```python
scanner = ChatCompletionAgent(
    service=AzureChatCompletion(deployment_name="gpt-4o", endpoint=ENDPOINT, api_key=KEY),
    name="Scanner",
    instructions="You are a security scanner...",
    plugins=[SemgrepPlugin(), GitDiffPlugin()],  # auto function-calling enabled by default
)
```

**Plugin pattern** — classes with `@kernel_function` methods:
```python
class SemgrepPlugin:
    @kernel_function(description="Run SAST scan on code")
    async def run_scan(self, code: Annotated[str, "Source code to scan"]) -> Annotated[str, "JSON findings"]:
        # Semgrep logic here
        return json.dumps(findings)
```

**Orchestration** — `SequentialOrchestration` + `InProcessRuntime` (experimental but functional):
```python
orchestration = SequentialOrchestration(members=[scanner, intelligence, remediation])
runtime = InProcessRuntime()
runtime.start()  # synchronous call
result = await orchestration.invoke(task="Analyze this PR...", runtime=runtime)
output = await result.get()  # final agent's response
await runtime.stop_when_idle()
```

**Agent invocation** (manual chaining alternative):
```python
# get_response() for simple request→response
response = await scanner.get_response(messages="Analyze this code...")
# response.content = text output, response.thread = ChatHistoryAgentThread

# invoke() for streaming intermediate steps (tool calls visible)
async for step in scanner.invoke(messages="...", on_intermediate_message=log_step):
    print(step.content)
```

**MCP integration** — GitHub MCP as SK plugin:
```python
async with MCPStdioPlugin(
    name="GitHub", command="npx",
    args=["-y", "@modelcontextprotocol/server-github"],
    env={"GITHUB_PERSONAL_ACCESS_TOKEN": token},
) as github_plugin:
    agent = ChatCompletionAgent(plugins=[github_plugin, OtherPlugin()], ...)
```

---

### Week-by-Week Plan (4 weeks)

---

### Week 1: Foundation + Scanner Agent (Days 1-7)

**Goal:** End-to-end webhook → Semantic Kernel agent → GitHub comment

**Day 1-2: Azure + Project Setup**
- Script Azure provisioning (don't click through portal manually):
  - Resource group, Azure OpenAI (GPT-4o deployment), Cosmos DB (free tier, NoSQL + Gremlin), Application Insights, Azure AI Foundry project
- Initialize Python project with `pyproject.toml`:
  - Dependencies: `semantic-kernel>=1.39`, `azure-cosmos`, `azure-identity`, `fastapi`, `uvicorn`, `pydantic`
- Create project structure:
  ```
  secureflow-ai/
  ├── src/
  │   ├── agents/              # SK ChatCompletionAgent definitions
  │   │   ├── scanner.py       # Scanner agent + system prompt
  │   │   ├── intelligence.py  # Intelligence agent (context + priority)
  │   │   └── remediation.py   # Remediation agent (fix + validate)
  │   ├── plugins/             # SK @kernel_function plugins
  │   │   ├── semgrep_plugin.py
  │   │   ├── github_plugin.py
  │   │   ├── pattern_plugin.py
  │   │   ├── risk_plugin.py
  │   │   └── fix_plugin.py
  │   ├── orchestrator.py      # SequentialOrchestration workflow
  │   ├── models.py            # Pydantic: Finding, Fix, RiskScore, Evidence
  │   └── main.py              # FastAPI webhook receiver
  ├── infra/                   # Bicep templates for Azure
  ├── tests/
  ├── pyproject.toml
  └── Dockerfile
  ```

**Day 3-4: Scanner Agent with SK Plugins**
- Build `SemgrepPlugin` class with `@kernel_function` methods:
  - `run_sast_scan(code, language)` → runs Semgrep, returns JSON findings
  - `scan_dependencies(manifest)` → runs Trivy, returns dependency vulns
- Build `GitDiffPlugin`:
  - `get_pr_diff(repo, pr_number)` → fetches diff via GitHub API
  - `get_file_content(repo, path, ref)` → fetches file content
- Create Scanner `ChatCompletionAgent`:
  - System prompt: role definition + output format (structured JSON findings)
  - Plugins: `[SemgrepPlugin(), GitDiffPlugin()]`
  - Auto function-calling enabled (default behavior)
- Test locally: `await scanner.get_response(messages="Scan this code: ...")` → verify it calls plugins and returns structured findings

**Day 5-6: GitHub Integration + Webhook**
- Build `GitHubPlugin` with `@kernel_function`:
  - `post_pr_review(repo, pr_number, comments)` — uses PR Review API for inline suggestions
  - `post_summary_comment(repo, pr_number, body)` — summary comment
  - `add_label(repo, pr_number, label)` — for confidence-based labeling
- FastAPI `POST /webhook` endpoint:
  - Validates GitHub webhook signature (`X-Hub-Signature-256`)
  - Filters for `pull_request` events with `action: opened|synchronize`
  - Extracts repo name, PR number, head SHA
  - Triggers Scanner agent asynchronously
- Deploy to Azure Container Apps for Week 1 (simple container deployment)

**Day 7: End-to-End Test**
- Create test repo with `vulnerable.py` (SQL injection, hardcoded secrets, path traversal)
- Create PR → verify webhook fires → Scanner Agent analyzes → posts comment with findings
- Check Application Insights for traces
- Fix any issues

**Week 1 Deliverable:** PR → Scanner Agent detects vulnerabilities → posts findings to PR

---

### Week 2: Intelligence + Remediation + Orchestration (Days 8-14)

**Goal:** Full 3-agent pipeline with confidence-based fix routing

**Day 8-9: Intelligence Agent (Context + Priority)**
- Build `PatternPlugin`:
  - `get_team_patterns(repo, vuln_type)` → queries Cosmos DB for historical fix patterns
  - `get_framework_info(repo)` → detects frameworks used in codebase
- Build `RiskScorerPlugin`:
  - `assess_risk(finding_json, code_context)` → multi-factor risk score
  - Factors: reachability, data sensitivity, exploit complexity, existing controls
  - Returns: priority (CRITICAL/HIGH/MEDIUM/LOW) + rationale
- Create Intelligence `ChatCompletionAgent`:
  - System prompt: "You contextualize and prioritize security findings. Filter noise. Only surface the top 3-5 critical issues with clear business rationale."
  - Plugins: `[PatternPlugin(), RiskScorerPlugin()]`
- Seed Cosmos DB with sample patterns (SQL injection → parameterized queries, secrets → env vars, etc.)

**Day 10-11: Remediation Agent**
- Build `FixGeneratorPlugin`:
  - `generate_fix(vuln_code, vuln_type, team_context)` → generates fix via Azure OpenAI
  - `validate_fix(code, language)` → AST parse check (compile validation)
  - `assess_confidence(finding, fix, context)` → returns confidence 0.0-1.0
- Build `GitHubSuggestionPlugin`:
  - `create_review_with_suggestions(repo, pr, commit_sha, findings_with_fixes)` → posts PR review with inline code suggestions using the correct Pull Request Review API
- Create Remediation `ChatCompletionAgent`:
  - System prompt includes confidence-based routing rules:
    - ">90% confidence: Mark as auto-applicable, post inline suggestion"
    - "70-90%: Post suggestion with [Review Required] warning"
    - "<70%: Flag for security team escalation"
  - Plugins: `[FixGeneratorPlugin(), GitHubSuggestionPlugin()]`

**Day 12-13: Multi-Agent Orchestration**
- Build `SecurityReviewWorkflow` in `orchestrator.py`:
  - **Option A (preferred):** Use `SequentialOrchestration`:
    ```python
    orchestration = SequentialOrchestration(
        members=[scanner_agent, intelligence_agent, remediation_agent]
    )
    runtime = InProcessRuntime()
    runtime.start()
    result = await orchestration.invoke(task=pr_analysis_prompt, runtime=runtime)
    final = await result.get()
    await runtime.stop_when_idle()
    ```
  - **Option B (fallback):** Manual chaining with `get_response()`:
    ```python
    scan_result = await scanner.get_response(messages=pr_diff)
    intel_result = await intelligence.get_response(messages=scan_result.content)
    fix_result = await remediation.get_response(messages=intel_result.content)
    ```
  - Option B is more reliable if `SequentialOrchestration` (experimental) has issues
- Store workflow results in Cosmos DB: findings, risk scores, fixes, confidence levels
- Update `main.py` to use orchestrator instead of standalone Scanner

**Day 14: Integration Test**
- Test full pipeline with multiple vulnerability types
- Verify each confidence tier works:
  - High-confidence SQL injection fix → auto-suggested inline
  - Medium-confidence fix → suggested with review warning
  - Low-confidence complex vuln → flagged for security team
- Verify Cosmos DB stores complete workflow state

**Week 2 Deliverable:** Full 3-agent pipeline. PRs get prioritized findings with inline fix suggestions and confidence-based routing.

---

### Week 3: Knowledge Base + Compliance + Production Deploy (Days 15-21)

**Goal:** Data grounding, compliance evidence, Foundry Agent Service deployment

**Day 15-16: Knowledge Base + Learning Loop (Data Grounding)**
- Use Cosmos DB NoSQL container `patterns` (simpler than Gremlin for solo dev):
  - Documents: `{id, cwe_id, vuln_type, fix_pattern, framework, language, repo, confidence, accepted_count, rejected_count}`
  - Query by vuln_type + language to find team's preferred fix patterns
- Add `KnowledgeBasePlugin` to Intelligence Agent:
  - `query_similar_fixes(vuln_type, language, repo)` → Cosmos DB query for historical patterns
  - `store_fix_outcome(finding, fix, accepted: bool)` → learn from PR merge/rejection
- Seed with ~20 common vulnerability fix patterns (SQL injection, XSS, SSRF, secrets, etc.)
- **Stretch goal:** Azure AI Search for vector embeddings (add if time permits)
- This is the "gets smarter over time" differentiator judges love

**Day 17-18: Compliance Evidence Generation**
- Create CWE → compliance mapping data (seeded in Cosmos DB):
  - CWE-89 (SQL Injection) → SOC2 CC6.1, PCI-DSS 6.5.1
  - CWE-798 (Hardcoded Credentials) → SOC2 CC6.1, PCI-DSS 3.2
  - CWE-78 (Command Injection) → SOC2 CC6.1, OWASP A03
- Add `CompliancePlugin` to Intelligence Agent:
  - `map_compliance(cwe_id)` → returns applicable frameworks + requirements
  - `generate_evidence(finding, fix, pr_data)` → creates audit-ready evidence document
  - `store_evidence(evidence)` → immutable record in Cosmos DB
- Evidence format: timestamp, PR#, vulnerability, remediation, compliance requirements addressed, approval chain

**Day 19-20: Deploy to Azure AI Foundry Agent Service**
- Create Hosting Adapter wrapper for the FastAPI app
- Containerize with Dockerfile (must use `--platform linux/amd64`)
- Push to Azure Container Registry
- Deploy via `azd` CLI to Foundry Agent Service
- Configure: agent sessions, RBAC, OpenTelemetry auto-collection
- Test end-to-end on deployed instance

**Day 21: Hardening + Observability**
- Circuit breaker pattern: If any agent fails, gracefully degrade (post partial results)
- OpenTelemetry custom spans for each agent step + each plugin call
- Rate limiting on webhook endpoint (prevent abuse)
- Secrets via Azure Key Vault + Managed Identity (not env vars or .env files)

**Week 3 Deliverable:** Production system on Foundry Agent Service with knowledge base, compliance evidence, and full observability.

---

### Week 4: Demo, Dashboard, Submission (Days 22-28)

**Goal:** Polished demo, minimal dashboard, submission package

**Day 22: Dashboard (Streamlit, ~3-4 hours)**
- Single Streamlit page with:
  - Metric cards: PRs analyzed, findings detected, fixes generated, time saved
  - Severity breakdown (pie chart via `st.plotly_chart`)
  - Recent findings feed from Cosmos DB
  - Fix acceptance rate (learning loop metric)
- Deploy as Azure Container App (one `streamlit run` command in Dockerfile)
- **Dashboard is supplementary** — the GitHub PR experience is the real UX

**Day 23-24: Demo Preparation + Recording**
- Create compelling test repo: the "ShopFast" scenario from `idea.md`
  - `payment_endpoint.py` with SQL injection, logged secrets, missing validation
  - `user_service.py` with path traversal, command injection
- Script 2-minute demo:
  1. (0:00-0:15) Hook: Split screen — 50+ findings from traditional scanner vs. "There's a better way"
  2. (0:15-0:30) Problem statement: Alert fatigue, context-free fixes, 5-hour reviews
  3. (0:30-1:30) Live demo:
     - Create PR with vulnerable payment endpoint
     - Show 3-agent pipeline running (Application Insights trace view)
     - PR comment appears: 3 critical issues with inline fix suggestions
     - Click "Commit suggestion" on one fix
     - Show compliance evidence auto-generated
  4. (1:30-1:50) Architecture: diagram showing SK agents, Azure services, MCP
  5. (1:50-2:00) Impact: Dashboard showing 60% faster reviews, 80% fewer false positives
- Record with OBS Studio, 1080p, good audio

**Day 25-26: Documentation + Architecture Diagram**
- README.md: Problem, solution, architecture diagram, tech stack, setup, demo link
- Architecture diagram (draw.io): Multi-agent flow with all Azure services labeled
- Code: Docstrings on all agents and plugins (judges review code quality)
- `.env.example` with all required variables documented

**Day 27-28: Final Testing + Submission**
- Full regression: test all vulnerability types, all confidence tiers
- Verify all Azure services healthy
- Tag release `v1.0-hackathon`
- Submit to hackathon portal with all required fields
- Backup: Pre-recorded demo video in case live demo fails at presentation

**Week 4 Deliverable:** Complete submission: deployed system + demo video + documentation.

---

### Key Files to Create

| File | Purpose | Key SK APIs Used |
|------|---------|------------------|
| `src/agents/scanner.py` | Scanner `ChatCompletionAgent` definition | `ChatCompletionAgent(service=, plugins=, instructions=)` |
| `src/agents/intelligence.py` | Intelligence `ChatCompletionAgent` definition | Same + Cosmos DB queries in plugins |
| `src/agents/remediation.py` | Remediation `ChatCompletionAgent` definition | Same + confidence routing logic |
| `src/plugins/semgrep_plugin.py` | `@kernel_function` wrapping Semgrep CLI | `@kernel_function`, `Annotated` params |
| `src/plugins/github_plugin.py` | `@kernel_function` for PR Review API | GitHub REST API for inline suggestions |
| `src/plugins/pattern_plugin.py` | `@kernel_function` querying Cosmos DB | NoSQL queries for team patterns |
| `src/plugins/risk_plugin.py` | `@kernel_function` for risk assessment | Multi-factor scoring logic |
| `src/plugins/fix_plugin.py` | `@kernel_function` for fix gen + AST validation | `ast.parse()` for validation |
| `src/plugins/compliance_plugin.py` | `@kernel_function` for CWE→compliance mapping | Cosmos DB lookups |
| `src/orchestrator.py` | `SequentialOrchestration` + `InProcessRuntime` | Full pipeline workflow |
| `src/models.py` | Pydantic: Finding, Fix, RiskScore, Evidence | Type-safe data flow between agents |
| `src/main.py` | FastAPI webhook + agent invocation | `webhook_signature` validation |
| `infra/main.bicep` | All Azure resources as IaC | Cosmos DB, OpenAI, App Insights, ACR |
| `dashboard/app.py` | Streamlit metrics dashboard | `st.metric`, `st.plotly_chart` |

### How This Scores on Judging Criteria

| Criterion (20% each) | Suggested Plan | Our Plan | Why Ours Scores Higher |
|---|---|---|---|
| **Technological Implementation** | ~12/20 | ~17/20 | Proper SK usage, `@kernel_function` plugins, Pydantic models, clean async architecture |
| **Agentic Design & Innovation** | ~4/20 | ~18/20 | Real `SequentialOrchestration`, 3 specialized `ChatCompletionAgent`s, confidence-based routing, knowledge graph learning |
| **Real-World Impact** | ~14/20 | ~17/20 | Same problem, but compliance evidence auto-gen + learning loop add production depth |
| **User Experience** | ~10/20 | ~16/20 | Inline PR suggestions via correct Review API (not issue comments), confidence labels |
| **Adherence to Category** | ~5/20 | ~18/20 | Semantic Kernel, Foundry Agent Service, MCP, Azure AI Search, Cosmos DB — all hero technologies genuinely used |
| **TOTAL** | **~45/100** | **~86/100** | |

### Verification Plan

1. **Plugin unit tests:** Each `@kernel_function` plugin tested with mock data, verify return format
2. **Agent unit tests:** Each `ChatCompletionAgent` tested with `get_response()` against mock service
3. **Orchestration test:** `SequentialOrchestration` pipeline produces correct handoff (Scanner→Intelligence→Remediation)
4. **Confidence routing test:** Create 3 test PRs triggering each tier (>90%, 70-90%, <70%), verify correct GitHub action taken
5. **Integration test:** Full webhook → orchestrator → PR comment/suggestion posted
6. **Cosmos DB test:** Findings stored, knowledge base queried, compliance evidence persisted
7. **Demo rehearsal:** Run through full demo flow 3 times before recording, verify timing under 2 minutes

### Risk Mitigations

| Risk | Mitigation |
|------|-----------|
| `SequentialOrchestration` is experimental | Fallback to manual chaining with `get_response()` (tested in parallel) |
| Semgrep too slow in container | Pre-pull rules at build time, cache results in Cosmos DB with TTL |
| Azure OpenAI rate limits | Retry with exponential backoff, use GPT-4o-mini for low-priority findings |
| Fix generation hallucinates | AST validation in `FixValidatorPlugin`, confidence <70% triggers escalation |
| Webhook floods during demo | Rate limit to 5 concurrent, queue excess with Azure Service Bus |
| Foundry Agent Service issues | Keep Container Apps deployment as fallback (same Docker image works both ways) |
