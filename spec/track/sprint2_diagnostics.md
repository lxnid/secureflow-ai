Sprint 2 Debug — 9 Fixes Applied  
 #: 1  
 Issue: GitHubPlugin resource leak  
 File(s): orchestrator.py, scanner.py, remediation.py  
 Fix: Shared GitHubPlugin created in orchestrator, passed to agent factories, closed in finally block  
 ────────────────────────────────────────  
 #: 2
Issue: Cosmos DB client never initialized
File(s): main.py
Fix: Initialize CosmosClient in FastAPI lifespan, store on app.state, pass to process_pr
────────────────────────────────────────
#: 3
Issue: get_response(messages=str) type
File(s): orchestrator.py
Fix: Verified SK v1.39+ accepts strings natively — no code change needed (false positive)
────────────────────────────────────────
#: 4
Issue: Remediation missing PR context
File(s): orchestrator.py, intelligence.py
Fix: Structured ## PR Context block in task message + "preserve it" instruction in Intelligence prompt + explicit context in remediation prompt
────────────────────────────────────────
#: 5
Issue: runtime.start() not awaited
File(s): orchestrator.py
Fix: Verified InProcessRuntime.start() is synchronous in SK v1.39 — no change needed (false positive)
────────────────────────────────────────
#: 6
Issue: Severity fallback uses vuln_type
File(s): main.py
Fix: Changed fallback from fix.get("vuln_type", "?") to "MEDIUM"
────────────────────────────────────────
#: 7
Issue: Pattern plugin CancelledError
File(s): pattern_plugin.py
Fix: Added explicit except asyncio.CancelledError: raise before generic Exception handler
────────────────────────────────────────
#: 8
Issue: JSON parse misses code blocks
File(s): orchestrator.py
Fix: Replaced string-split with re.findall + reverse iteration over all fenced blocks
────────────────────────────────────────
#: 9
Issue: Cosmos DB lifecycle unmanaged
File(s): main.py
Fix: Full lifecycle in lifespan: init with try/except, await cosmos_client.close() on shutdown
★ Insight ─────────────────────────────────────
Resource lifecycle in async web apps: The Cosmos DB and GitHubPlugin fixes illustrate a fundamental pattern — long-lived async clients (HTTP pools, database
connections) should be created once at startup and cleaned up at shutdown, not per-request. FastAPI's lifespan context manager and app.state provide the
canonical hook for this. The try/finally pattern in the orchestrator ensures cleanup even when agents throw exceptions mid-pipeline.

Context propagation in multi-agent systems: Issue #4 highlights a unique challenge in sequential agent orchestration — each agent only receives the previous
agent's output, not the original task. Without explicit "preserve this context" instructions, critical metadata (repo name, PR number) gets lost by the
middle of the pipeline. This is a form of the "telephone game" problem in agentic architectures.
