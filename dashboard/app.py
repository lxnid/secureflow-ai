"""SecureFlow AI — Security Intelligence Dashboard.

Single-page Streamlit dashboard showing pipeline metrics, finding
severity distribution, fix acceptance rates, and compliance coverage.

Run: streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─── Page config ───────────────────────────────────────────────
st.set_page_config(
    page_title="SecureFlow AI — Dashboard",
    page_icon=":shield:",
    layout="wide",
)


# ─── Data loading ──────────────────────────────────────────────
@st.cache_data(ttl=60)
def load_data() -> dict:
    """Load pipeline data from Cosmos DB or fall back to demo data."""
    cosmos_endpoint = os.getenv("COSMOS_ENDPOINT", "")
    cosmos_key = os.getenv("COSMOS_KEY", "")
    cosmos_database = os.getenv("COSMOS_DATABASE", "secureflow")

    if cosmos_endpoint and cosmos_key:
        try:
            from azure.cosmos import CosmosClient

            client = CosmosClient(cosmos_endpoint, {"masterKey": cosmos_key})
            db = client.get_database_client(cosmos_database)
            findings_container = db.get_container_client("findings")
            evidence_container = db.get_container_client("evidence")
            patterns_container = db.get_container_client("patterns")

            # Query pipeline results
            results = list(findings_container.query_items(
                query="SELECT * FROM c ORDER BY c._ts DESC",
                enable_cross_partition_query=True,
            ))
            evidence = list(evidence_container.query_items(
                query="SELECT * FROM c ORDER BY c._ts DESC",
                enable_cross_partition_query=True,
            ))
            patterns = list(patterns_container.query_items(
                query="SELECT * FROM c",
                enable_cross_partition_query=True,
            ))
            return {
                "results": results,
                "evidence": evidence,
                "patterns": patterns,
                "source": "cosmos",
            }
        except Exception as e:
            st.warning(f"Cosmos DB unavailable: {e}. Using demo data.")

    return _demo_data()


def _demo_data() -> dict:
    """Generate realistic demo data for the dashboard."""
    now = datetime.now(timezone.utc)
    results = [
        {
            "id": f"pr-{i}",
            "pr_number": 100 + i,
            "repo": "acme/shopfast",
            "timestamp": (now - timedelta(hours=i * 6)).isoformat(),
            "status": "completed",
            "duration_seconds": 12.5 + i * 2.3,
            "orchestration_mode": "manual" if i % 3 == 0 else "sequential",
            "fixes": [
                {
                    "vuln_type": vt,
                    "severity": sev,
                    "confidence": conf,
                    "tier": (
                        "auto_apply" if conf >= 0.9
                        else "review_required" if conf >= 0.7
                        else "escalate"
                    ),
                    "is_valid": True,
                    "file_path": fp,
                }
                for vt, sev, conf, fp in [
                    ("sql_injection", "CRITICAL", 0.93, "app/routes/payment.py"),
                    ("hardcoded_secret", "HIGH", 0.91, "app/config.py"),
                    ("xss", "HIGH", 0.78, "app/routes/users.py"),
                    ("path_traversal", "MEDIUM", 0.82, "app/services/files.py"),
                    ("command_injection", "CRITICAL", 0.65, "app/services/deploy.py"),
                ][: 3 + (i % 3)]
            ],
        }
        for i in range(12)
    ]

    evidence = [
        {
            "id": f"ev-{i}",
            "pr_number": 100 + (i % 12),
            "repo": "acme/shopfast",
            "timestamp": (now - timedelta(hours=i * 4)).isoformat(),
            "finding": {"cwe_id": cwe, "severity": sev, "title": title},
            "remediation": {"confidence": conf, "tier": tier},
            "compliance": {
                "frameworks_affected": fws,
                "requirements_addressed": [
                    {"framework": fw, "requirement": req}
                    for fw, req in zip(fws, reqs)
                ],
            },
            "status": "remediated",
        }
        for i, (cwe, sev, title, conf, tier, fws, reqs) in enumerate([
            ("CWE-89", "CRITICAL", "SQL Injection in payment query", 0.93, "auto_apply", ["SOC2", "PCI-DSS", "OWASP"], ["CC6.1", "6.5.1", "A03:2021"]),
            ("CWE-798", "HIGH", "Hardcoded API key in config", 0.91, "auto_apply", ["SOC2", "PCI-DSS"], ["CC6.1", "8.2.1"]),
            ("CWE-79", "HIGH", "XSS in user profile endpoint", 0.78, "review_required", ["OWASP", "PCI-DSS"], ["A03:2021", "6.5.7"]),
            ("CWE-22", "MEDIUM", "Path traversal in file service", 0.82, "review_required", ["OWASP"], ["A01:2021"]),
            ("CWE-78", "CRITICAL", "Command injection in deploy", 0.65, "escalate", ["OWASP", "SOC2"], ["A03:2021", "CC6.1"]),
            ("CWE-327", "MEDIUM", "Weak cryptography in auth", 0.85, "review_required", ["PCI-DSS", "HIPAA"], ["4.1", "164.312(e)(1)"]),
            ("CWE-89", "CRITICAL", "SQL Injection in search", 0.95, "auto_apply", ["SOC2", "PCI-DSS", "OWASP"], ["CC6.1", "6.5.1", "A03:2021"]),
            ("CWE-918", "HIGH", "SSRF in webhook handler", 0.72, "review_required", ["OWASP", "SOC2"], ["A10:2021", "CC6.6"]),
        ])
    ]

    patterns = [
        {"vuln_type": "sql_injection", "language": "python", "confidence": 0.92, "accepted_count": 14, "rejected_count": 1},
        {"vuln_type": "hardcoded_secret", "language": "python", "confidence": 0.95, "accepted_count": 18, "rejected_count": 1},
        {"vuln_type": "xss", "language": "javascript", "confidence": 0.81, "accepted_count": 8, "rejected_count": 2},
        {"vuln_type": "path_traversal", "language": "python", "confidence": 0.78, "accepted_count": 5, "rejected_count": 1},
        {"vuln_type": "command_injection", "language": "python", "confidence": 0.68, "accepted_count": 3, "rejected_count": 2},
        {"vuln_type": "ssrf", "language": "python", "confidence": 0.60, "accepted_count": 2, "rejected_count": 2},
    ]

    return {"results": results, "evidence": evidence, "patterns": patterns, "source": "demo"}


# ─── Dashboard ─────────────────────────────────────────────────
def main():
    data = load_data()
    results = data["results"]
    evidence = data["evidence"]
    patterns = data["patterns"]
    source = data["source"]

    # Header
    st.markdown("# :shield: SecureFlow AI")
    st.markdown("**AI-Powered Multi-Agent DevSecOps Intelligence Platform**")
    if source == "demo":
        st.caption(":information_source: Showing demo data — connect Cosmos DB for live metrics")
    st.divider()

    # ── Row 1: KPI Cards ──────────────────────────────────────
    total_prs = len(results)
    total_findings = sum(len(r.get("fixes", [])) for r in results)
    total_fixes = sum(
        1 for r in results for f in r.get("fixes", []) if f.get("is_valid")
    )
    avg_duration = (
        sum(r.get("duration_seconds", 0) for r in results) / total_prs
        if total_prs > 0
        else 0
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("PRs Analyzed", total_prs)
    c2.metric("Findings Detected", total_findings)
    c3.metric("Fixes Generated", total_fixes)
    c4.metric("Avg Pipeline Time", f"{avg_duration:.1f}s")

    st.divider()

    # ── Row 2: Charts ─────────────────────────────────────────
    col_left, col_right = st.columns(2)

    # Severity distribution (pie chart)
    with col_left:
        st.subheader("Finding Severity Distribution")
        severities = []
        for r in results:
            for f in r.get("fixes", []):
                severities.append(f.get("severity", "MEDIUM"))

        if severities:
            sev_counts = {}
            for s in severities:
                sev_counts[s] = sev_counts.get(s, 0) + 1
            fig_sev = px.pie(
                names=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                color=list(sev_counts.keys()),
                color_discrete_map={
                    "CRITICAL": "#dc3545",
                    "HIGH": "#fd7e14",
                    "MEDIUM": "#ffc107",
                    "LOW": "#6c757d",
                },
                hole=0.4,
            )
            fig_sev.update_layout(margin=dict(t=20, b=20, l=20, r=20), height=300)
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No findings yet")

    # Confidence tier distribution (bar chart)
    with col_right:
        st.subheader("Fix Confidence Tiers")
        tiers = {"auto_apply": 0, "review_required": 0, "escalate": 0}
        for r in results:
            for f in r.get("fixes", []):
                tier = f.get("tier", "escalate")
                tiers[tier] = tiers.get(tier, 0) + 1

        fig_tier = go.Figure(data=[
            go.Bar(
                x=["Auto-Apply\n(>90%)", "Review Required\n(70-90%)", "Escalated\n(<70%)"],
                y=[tiers["auto_apply"], tiers["review_required"], tiers["escalate"]],
                marker_color=["#28a745", "#ffc107", "#dc3545"],
                text=[tiers["auto_apply"], tiers["review_required"], tiers["escalate"]],
                textposition="auto",
            )
        ])
        fig_tier.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            height=300,
            yaxis_title="Count",
            showlegend=False,
        )
        st.plotly_chart(fig_tier, use_container_width=True)

    st.divider()

    # ── Row 3: Compliance + Patterns ──────────────────────────
    col_comp, col_pat = st.columns(2)

    # Compliance coverage
    with col_comp:
        st.subheader("Compliance Coverage")
        frameworks: dict[str, int] = {}
        for ev in evidence:
            for fw in ev.get("compliance", {}).get("frameworks_affected", []):
                frameworks[fw] = frameworks.get(fw, 0) + 1

        if frameworks:
            fig_comp = go.Figure(data=[
                go.Bar(
                    x=list(frameworks.keys()),
                    y=list(frameworks.values()),
                    marker_color=["#0d6efd", "#6610f2", "#6f42c1", "#d63384"][
                        : len(frameworks)
                    ],
                    text=list(frameworks.values()),
                    textposition="auto",
                )
            ])
            fig_comp.update_layout(
                margin=dict(t=20, b=20, l=20, r=20),
                height=280,
                yaxis_title="Evidence Documents",
                showlegend=False,
            )
            st.plotly_chart(fig_comp, use_container_width=True)
            st.caption(f"{len(evidence)} audit-ready evidence documents generated")
        else:
            st.info("No compliance evidence yet")

    # Pattern learning (knowledge base)
    with col_pat:
        st.subheader("Knowledge Base — Fix Patterns")
        if patterns:
            pattern_data = []
            for p in patterns:
                total = p.get("accepted_count", 0) + p.get("rejected_count", 0)
                acceptance_rate = (
                    p.get("accepted_count", 0) / total * 100 if total > 0 else 0
                )
                pattern_data.append({
                    "Vulnerability": p.get("vuln_type", "?").replace("_", " ").title(),
                    "Language": p.get("language", "?"),
                    "Confidence": f"{p.get('confidence', 0):.0%}",
                    "Accepted": p.get("accepted_count", 0),
                    "Rejected": p.get("rejected_count", 0),
                    "Rate": f"{acceptance_rate:.0f}%",
                })
            st.dataframe(
                pattern_data,
                use_container_width=True,
                hide_index=True,
                height=280,
            )
            total_accepted = sum(p.get("accepted_count", 0) for p in patterns)
            total_rejected = sum(p.get("rejected_count", 0) for p in patterns)
            total_all = total_accepted + total_rejected
            if total_all > 0:
                st.caption(
                    f"Overall acceptance rate: **{total_accepted / total_all:.0%}** "
                    f"({total_accepted} accepted / {total_all} total)"
                )
        else:
            st.info("No patterns in knowledge base yet")

    st.divider()

    # ── Row 4: Recent activity table ──────────────────────────
    st.subheader("Recent Pipeline Activity")
    if results:
        activity = []
        for r in results[:10]:
            fix_count = len(r.get("fixes", []))
            auto_count = sum(1 for f in r.get("fixes", []) if f.get("tier") == "auto_apply")
            activity.append({
                "PR": f"#{r.get('pr_number', '?')}",
                "Repository": r.get("repo", "?"),
                "Findings": fix_count,
                "Auto-Applied": auto_count,
                "Duration": f"{r.get('duration_seconds', 0):.1f}s",
                "Mode": r.get("orchestration_mode", "?"),
                "Status": r.get("status", "?"),
            })
        st.dataframe(activity, use_container_width=True, hide_index=True)
    else:
        st.info("No pipeline runs yet")

    # ── Footer ────────────────────────────────────────────────
    st.divider()
    st.caption(
        "SecureFlow AI — AI-Powered Multi-Agent DevSecOps Intelligence Platform | "
        "Microsoft AI Dev Days Hackathon 2025"
    )


if __name__ == "__main__":
    main()
