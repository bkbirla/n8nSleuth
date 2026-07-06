#!/usr/bin/env python3
"""Analyze exported n8n workflows for common security issues."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_WORKFLOWS_FILE = Path(__file__).parent / "workflows.json"
DEFAULT_JSON_OUT = Path(__file__).parent / "security_report.json"
DEFAULT_HTML_OUT = Path(__file__).parent / "security_report.html"

IGNORE_KEYS = {
    "nodeCredentialType",
    "genericAuthType",
    "authentication",
    "type",
    "credentialType",
    "resource",
    "operation",
    "mode",
    "method",
}
IGNORE_VALUES = {
    "genericCredentialType",
    "predefinedCredentialType",
    "httpHeaderAuth",
    "httpBasicAuth",
    "oAuth2Api",
    "none",
    "headerAuth",
    "basicAuth",
}

SECRET_VALUE_PATTERNS = [
    (re.compile(r"^Bearer\s+[A-Za-z0-9\-_\.=]{20,}$", re.I), "hardcoded_bearer_token"),
    (re.compile(r"^Basic\s+[A-Za-z0-9+/=]{10,}$", re.I), "hardcoded_basic_auth"),
    (re.compile(r"^eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$"), "hardcoded_jwt"),
    (re.compile(r"^sk-[A-Za-z0-9]{20,}$"), "hardcoded_openai_key"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "hardcoded_aws_access_key"),
    (re.compile(r"^xox[baprs]-[A-Za-z0-9\-]+$"), "hardcoded_slack_token"),
    (re.compile(r"^ghp_[A-Za-z0-9]{20,}$"), "hardcoded_github_token"),
    (re.compile(r"^glpat-[A-Za-z0-9\-_]+$"), "hardcoded_gitlab_token"),
]

DANGEROUS_CODE_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval() usage"),
    (re.compile(r"\bFunction\s*\("), "Function() constructor"),
    (re.compile(r"child_process"), "child_process access"),
    (re.compile(r"require\s*\(\s*['\"]fs['\"]"), "filesystem access via fs"),
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]"), "child_process require"),
    (re.compile(r"process\.env"), "process.env access (may leak secrets)"),
    (re.compile(r"(?<![.\w])exec\s*\("), "exec() standalone call"),
]

# Real n8n SQL-injection vector: an expression interpolated *inside* a SQL
# string literal, or concatenated onto a query, rather than passed as a
# parameter. n8n does not use JS "+" concatenation, so we look for {{ }}
# interpolation adjacent to quotes / comparison operators inside a query.
SQL_KEYWORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|MERGE|UPSERT)\b", re.I)
SQL_INLINE_EXPR_PATTERNS = [
    re.compile(r"'[^']*\{\{"),        # opening quote then expression:  '{{ ... }}
    re.compile(r"\}\}[^']*'"),        # expression then closing quote:  {{ ... }}'
    re.compile(r"[=<>]\s*\{\{"),      # comparison directly with expression:  = {{ ... }}
    re.compile(r"\+\s*\{\{"),         # concatenation onto expression
]
DB_NODE_HINTS = ("postgres", "mysql", "microsoftsql", "mssql", "snowflake",
                 "cratedb", "questdb", "timescaledb", "cockroachdb", "oracle")

# Secret patterns for scanning embedded blobs (pinData / staticData). Unlike
# SECRET_VALUE_PATTERNS these use search (not full-match) since the secret is
# buried inside a larger serialized payload.
EMBEDDED_SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{10,}"), "JWT"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(r"\bglpat-[A-Za-z0-9\-_]{10,}"), "GitLab token"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]{20,}", re.I), "Bearer token"),
]

OFFICIAL_NODE_PREFIXES = ("n8n-nodes-base.", "@n8n/")

# Node types where a field named "secret" is a legitimate parameter, not a hardcoded credential.
LEGITIMATE_SECRET_FIELDS: dict[str, set[str]] = {
    "n8n-nodes-base.crypto": {"secret"},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

ISSUE_LABELS = {
    "hardcoded_bearer_token": "Hardcoded Bearer token",
    "hardcoded_basic_auth": "Hardcoded Basic auth",
    "hardcoded_jwt": "Hardcoded JWT",
    "hardcoded_openai_key": "Hardcoded OpenAI API key",
    "hardcoded_aws_access_key": "Hardcoded AWS access key",
    "hardcoded_slack_token": "Hardcoded Slack token",
    "hardcoded_github_token": "Hardcoded GitHub token",
    "hardcoded_gitlab_token": "Hardcoded GitLab token",
    "hardcoded_secret_field": "Hardcoded secret in sensitive field",
    "hardcoded_auth_header": "Hardcoded auth header value",
    "unauthenticated_webhook": "Unauthenticated webhook",
    "webhook_get_no_response_node": "GET webhook without response node",
    "webhook_cors_wildcard": "Webhook CORS allows any origin",
    "ssl_verification_disabled": "SSL verification disabled",
    "cleartext_http": "Cleartext HTTP (no TLS)",
    "dangerous_code_pattern": "Dangerous code pattern",
    "sql_injection_risk": "SQL injection risk",
    "secret_in_url": "Secret in URL",
    "execute_command_node": "Shell command execution",
    "ssh_command_execution": "SSH command execution",
    "secret_in_pinned_data": "Secret in pinned data",
    "secret_in_static_data": "Secret in static data",
    "community_node": "Community/custom node",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze exported n8n workflows for security issues."
    )
    parser.add_argument(
        "--workflows",
        type=Path,
        default=DEFAULT_WORKFLOWS_FILE,
        help=f"Path to workflows export JSON (default: {DEFAULT_WORKFLOWS_FILE.name})",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_JSON_OUT,
        help=f"JSON report output path (default: {DEFAULT_JSON_OUT.name})",
    )
    parser.add_argument(
        "--html-out",
        type=Path,
        default=DEFAULT_HTML_OUT,
        help=f"HTML report output path (default: {DEFAULT_HTML_OUT.name})",
    )
    return parser.parse_args()


def is_expression(value: str) -> bool:
    stripped = value.strip()
    return bool(
        stripped.startswith("={{")
        or stripped.startswith("{{")
        or stripped.startswith("=Bearer {{")
        or "$node[" in stripped
        or "$json." in stripped
        or "$(" in stripped
        or "$credentials" in stripped
        or "$vars." in stripped
    )


def scan_value_for_secrets(key: str, value: str, path: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if key in IGNORE_KEYS or value.strip() in IGNORE_VALUES or is_expression(value):
        return findings

    for pattern, issue_type in SECRET_VALUE_PATTERNS:
        if pattern.match(value.strip()):
            findings.append({"type": issue_type, "path": path, "key": key})
            return findings

    if key.lower() in ("authorization", "x-api-key", "api-key", "apikey") and len(value) >= 16:
        if re.search(r"Bearer\s+[A-Za-z0-9\-_\.=]{20,}", value, re.I) or re.match(
            r"^eyJ[A-Za-z0-9\-_]+\.", value.strip()
        ):
            findings.append({"type": "hardcoded_auth_header", "path": path, "key": key})

    if re.search(r"(password|secret|apikey|api_key)", key, re.I) and len(value.strip()) >= 12:
        findings.append({"type": "hardcoded_secret_field", "path": path, "key": key})

    return findings


def walk_object(obj: Any, path: str = "") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in IGNORE_KEYS:
                continue
            child_path = f"{path}.{key}" if path else key
            if isinstance(value, str):
                findings.extend(scan_value_for_secrets(key, value, child_path))
            else:
                findings.extend(walk_object(value, child_path))
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            findings.extend(walk_object(item, f"{path}[{index}]"))

    return findings


def analyze_node(node: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    node_type = node.get("type", "")
    node_name = node.get("name", "unnamed")
    params = node.get("parameters", {})

    if node_type == "n8n-nodes-base.webhook":
        auth = params.get("authentication")
        if not auth or str(auth).lower() == "none":
            path = params.get("path", "unknown")
            method = params.get("httpMethod", "POST")
            issues.append(
                {
                    "severity": "high",
                    "type": "unauthenticated_webhook",
                    "node": node_name,
                    "detail": f"path='{path}', method={method}",
                }
            )
        if params.get("httpMethod") == "GET" and params.get("responseMode") != "responseNode":
            issues.append(
                {
                    "severity": "medium",
                    "type": "webhook_get_no_response_node",
                    "node": node_name,
                    "detail": "GET webhook may expose data in URLs/logs",
                }
            )
        webhook_opts = params.get("options") or {}
        if isinstance(webhook_opts, dict) and webhook_opts.get("allowedOrigins") == "*":
            issues.append(
                {
                    "severity": "medium",
                    "type": "webhook_cors_wildcard",
                    "node": node_name,
                    "detail": "allowedOrigins='*' (any site can call this webhook from a browser)",
                }
            )

    options = params.get("options") or {}
    if isinstance(options, dict) and options.get("allowUnauthorizedCerts"):
        issues.append(
            {
                "severity": "high",
                "type": "ssl_verification_disabled",
                "node": node_name,
                "detail": "allowUnauthorizedCerts=true",
            }
        )

    allowed_secret_fields = LEGITIMATE_SECRET_FIELDS.get(node_type, set())
    for finding in walk_object(params):
        if (
            finding["type"] == "hardcoded_secret_field"
            and finding["key"] in allowed_secret_fields
        ):
            continue
        issues.append(
            {
                "severity": "critical",
                "type": finding["type"],
                "node": node_name,
                "detail": f"Field '{finding['key']}' at {finding['path']}",
            }
        )

    if node_type == "n8n-nodes-base.code":
        code = params.get("jsCode") or params.get("pythonCode") or ""
        for pattern, desc in DANGEROUS_CODE_PATTERNS:
            if pattern.search(code):
                issues.append(
                    {
                        "severity": "medium",
                        "type": "dangerous_code_pattern",
                        "node": node_name,
                        "detail": desc,
                    }
                )

    if any(hint in node_type.lower() for hint in DB_NODE_HINTS):
        for field in ("query", "sql", "rawQuery", "queryString", "statement"):
            val = params.get(field)
            if isinstance(val, str) and SQL_KEYWORD.search(val):
                if any(pattern.search(val) for pattern in SQL_INLINE_EXPR_PATTERNS):
                    issues.append(
                        {
                            "severity": "high",
                            "type": "sql_injection_risk",
                            "node": node_name,
                            "detail": (
                                f"Expression interpolated into SQL string in '{field}' "
                                "(use query parameters instead)"
                            ),
                        }
                    )
                    break

    url = params.get("url", "")
    if isinstance(url, str) and url.strip():
        if re.search(r"[?&](api[_-]?key|token|password|secret)=", url, re.I):
            if not is_expression(url):
                issues.append(
                    {
                        "severity": "high",
                        "type": "secret_in_url",
                        "node": node_name,
                        "detail": "Credentials appear in URL query string",
                    }
                )
        if re.match(r"^http://", url.strip(), re.I) and not re.search(
            r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\.local\b", url, re.I
        ):
            issues.append(
                {
                    "severity": "medium",
                    "type": "cleartext_http",
                    "node": node_name,
                    "detail": f"Request over unencrypted HTTP: {url[:80]}",
                }
            )

    if node_type and not node_type.startswith(OFFICIAL_NODE_PREFIXES):
        issues.append(
            {
                "severity": "low",
                "type": "community_node",
                "node": node_name,
                "detail": f"Third-party node '{node_type}' (verify source/supply-chain trust)",
            }
        )

    if node_type == "n8n-nodes-base.executeCommand":
        issues.append(
            {
                "severity": "critical",
                "type": "execute_command_node",
                "node": node_name,
                "detail": "Workflow executes shell commands on the n8n host",
            }
        )

    if node_type == "n8n-nodes-base.ssh":
        issues.append(
            {
                "severity": "high",
                "type": "ssh_command_execution",
                "node": node_name,
                "detail": "Workflow executes remote SSH commands",
            }
        )

    return issues


def scan_embedded_blob(blob: Any) -> list[str]:
    """Return distinct secret kinds found in a serialized data blob."""
    if not blob:
        return []
    text = json.dumps(blob)
    found = []
    for pattern, label in EMBEDDED_SECRET_PATTERNS:
        if pattern.search(text) and label not in found:
            found.append(label)
    return found


def analyze_workflow(workflow: dict[str, Any]) -> dict[str, Any] | None:
    all_issues: list[dict[str, Any]] = []

    for node in workflow.get("nodes", []):
        all_issues.extend(analyze_node(node))

    for kind, issue_type in (("pinData", "secret_in_pinned_data"), ("staticData", "secret_in_static_data")):
        secret_kinds = scan_embedded_blob(workflow.get(kind))
        if secret_kinds:
            all_issues.append(
                {
                    "severity": "critical",
                    "type": issue_type,
                    "node": f"(workflow {kind})",
                    "detail": f"{kind} contains: {', '.join(secret_kinds)}",
                }
            )

    has_public_webhook = any(i["type"] == "unauthenticated_webhook" for i in all_issues)
    if workflow.get("active") and has_public_webhook:
        for issue in all_issues:
            if issue["type"] == "unauthenticated_webhook":
                issue["severity"] = "critical"

    if not all_issues:
        return None

    seen = set()
    unique_issues = []
    for issue in all_issues:
        key = (issue["type"], issue["node"], issue["detail"])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    unique_issues.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    return {
        "id": workflow.get("id"),
        "name": workflow.get("name"),
        "active": workflow.get("active", False),
        "issue_count": len(unique_issues),
        "issues": unique_issues,
    }


def build_report(workflows: list[dict[str, Any]], source_file: Path) -> dict[str, Any]:
    results = []
    for workflow in workflows:
        result = analyze_workflow(workflow)
        if result:
            results.append(result)

    results.sort(
        key=lambda w: (
            -sum(1 for i in w["issues"] if i["severity"] == "critical"),
            -w["issue_count"],
        )
    )

    by_severity: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    for result in results:
        for issue in result["issues"]:
            by_severity[issue["severity"]] += 1
            by_type[issue["type"]] += 1

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "sourceFile": str(source_file),
        "total_workflows": len(workflows),
        "workflows_with_issues": len(results),
        "summary_by_severity": dict(by_severity),
        "summary_by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
        "workflows": results,
    }


def issue_label(issue_type: str) -> str:
    return ISSUE_LABELS.get(issue_type, issue_type.replace("_", " ").title())


def render_html_report(report: dict[str, Any]) -> str:
    severity_counts = report.get("summary_by_severity", {})
    type_counts = report.get("summary_by_type", {})
    workflows = report.get("workflows", [])

    def esc(value: Any) -> str:
        return html.escape(str(value))

    summary_cards = [
        ("Total workflows", report.get("total_workflows", 0), "card-neutral"),
        ("With issues", report.get("workflows_with_issues", 0), "card-warn"),
        ("Critical findings", severity_counts.get("critical", 0), "card-critical"),
        ("High findings", severity_counts.get("high", 0), "card-high"),
        ("Medium findings", severity_counts.get("medium", 0), "card-medium"),
    ]

    cards_html = "\n".join(
        f"""        <div class="card {css}">
          <div class="card-value">{esc(count)}</div>
          <div class="card-label">{esc(label)}</div>
        </div>"""
        for label, count, css in summary_cards
    )

    type_rows = "\n".join(
        f"          <tr><td>{esc(issue_label(t))}</td><td>{esc(c)}</td></tr>"
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1])
    )

    workflow_sections = []
    for index, workflow in enumerate(workflows, start=1):
        status = "Active" if workflow.get("active") else "Inactive"
        status_class = "status-active" if workflow.get("active") else "status-inactive"
        issue_rows = "\n".join(
            f"""              <tr>
                <td><span class="sev sev-{esc(issue['severity'])}">{esc(issue['severity'])}</span></td>
                <td>{esc(issue_label(issue['type']))}</td>
                <td>{esc(issue['node'])}</td>
                <td>{esc(issue['detail'])}</td>
              </tr>"""
            for issue in workflow.get("issues", [])
        )
        workflow_sections.append(
            f"""      <details class="workflow" {'open' if index <= 5 else ''}>
        <summary>
          <span class="workflow-index">{index}</span>
          <span class="workflow-name">{esc(workflow.get('name', 'Unnamed'))}</span>
          <span class="badge {status_class}">{status}</span>
          <span class="issue-count">{esc(workflow.get('issue_count', 0))} issue(s)</span>
        </summary>
        <div class="workflow-body">
          <p class="meta">Workflow ID: <code>{esc(workflow.get('id', ''))}</code></p>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Issue</th>
                <th>Node</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
{issue_rows}
            </tbody>
          </table>
        </div>
      </details>"""
        )

    workflows_html = "\n".join(workflow_sections) if workflow_sections else (
        '      <p class="empty">No security issues detected.</p>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>n8n Security Report</title>
  <style>
    :root {{
      --bg: #0f1419;
      --surface: #1a2332;
      --border: #2d3a4d;
      --text: #e6edf3;
      --muted: #8b949e;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #3fb950;
      --accent: #58a6ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    header {{
      padding: 2rem 2rem 1rem;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #162032 0%, var(--bg) 100%);
    }}
    header h1 {{ margin: 0 0 0.25rem; font-size: 1.75rem; }}
    header p {{ margin: 0; color: var(--muted); font-size: 0.95rem; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.25rem;
    }}
    .card-value {{ font-size: 1.75rem; font-weight: 700; }}
    .card-label {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.25rem; }}
    .card-critical .card-value {{ color: var(--critical); }}
    .card-high .card-value {{ color: var(--high); }}
    .card-medium .card-value {{ color: var(--medium); }}
    .card-warn .card-value {{ color: var(--accent); }}
    section {{ margin-bottom: 2rem; }}
    section h2 {{
      font-size: 1.15rem;
      margin: 0 0 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    .type-table {{ background: var(--surface); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }}
    .workflow {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 0.75rem;
      overflow: hidden;
    }}
    .workflow summary {{
      cursor: pointer;
      list-style: none;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.85rem 1rem;
      user-select: none;
    }}
    .workflow summary::-webkit-details-marker {{ display: none; }}
    .workflow summary::before {{
      content: "▸";
      color: var(--muted);
      transition: transform 0.15s ease;
    }}
    .workflow[open] summary::before {{ transform: rotate(90deg); }}
    .workflow-name {{ flex: 1; font-weight: 600; }}
    .workflow-index {{ color: var(--muted); min-width: 2rem; }}
    .workflow-body {{ padding: 0 1rem 1rem; border-top: 1px solid var(--border); }}
    .meta {{ color: var(--muted); font-size: 0.85rem; margin: 0.75rem 0; }}
    code {{ background: #0d1117; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }}
    .badge, .issue-count {{
      font-size: 0.75rem;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      border: 1px solid var(--border);
    }}
    .status-active {{ color: var(--low); border-color: #238636; }}
    .status-inactive {{ color: var(--muted); }}
    .issue-count {{ color: var(--accent); }}
    .sev {{
      display: inline-block;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
    }}
    .sev-critical {{ background: rgba(248,81,73,0.15); color: var(--critical); }}
    .sev-high {{ background: rgba(219,109,40,0.15); color: var(--high); }}
    .sev-medium {{ background: rgba(210,153,34,0.15); color: var(--medium); }}
    .sev-low {{ background: rgba(63,185,80,0.15); color: var(--low); }}
    .empty {{ color: var(--muted); }}
    .toolbar {{
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }}
    .toolbar input {{
      flex: 1;
      min-width: 220px;
      padding: 0.55rem 0.75rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: #0d1117;
      color: var(--text);
    }}
    .toolbar button {{
      padding: 0.55rem 0.9rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text);
      cursor: pointer;
    }}
    .toolbar button:hover {{ border-color: var(--accent); }}
    .hidden {{ display: none !important; }}
  </style>
</head>
<body>
  <header>
    <h1>n8n Workflow Security Report</h1>
    <p>Generated {esc(report.get('generatedAt', ''))} · Source: {esc(report.get('sourceFile', ''))}</p>
  </header>
  <main>
    <div class="cards">
{cards_html}
    </div>

    <section>
      <h2>Findings by type</h2>
      <div class="type-table">
        <table>
          <thead><tr><th>Issue type</th><th>Count</th></tr></thead>
          <tbody>
{type_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Affected workflows ({esc(len(workflows))})</h2>
      <div class="toolbar">
        <input id="search" type="search" placeholder="Filter by workflow name, node, or issue type…">
        <button type="button" id="expand-all">Expand all</button>
        <button type="button" id="collapse-all">Collapse all</button>
      </div>
{workflows_html}
    </section>
  </main>
  <script>
    const search = document.getElementById('search');
    const items = [...document.querySelectorAll('.workflow')];

    search?.addEventListener('input', () => {{
      const q = search.value.trim().toLowerCase();
      items.forEach((item) => {{
        const text = item.textContent.toLowerCase();
        item.classList.toggle('hidden', q && !text.includes(q));
      }});
    }});

    document.getElementById('expand-all')?.addEventListener('click', () => {{
      items.forEach((item) => {{ item.open = true; }});
    }});

    document.getElementById('collapse-all')?.addEventListener('click', () => {{
      items.forEach((item) => {{ item.open = false; }});
    }});
  </script>
</body>
</html>
"""


def main() -> int:
    args = parse_args()

    if not args.workflows.exists():
        print(f"Error: {args.workflows} not found", file=sys.stderr)
        return 1

    with open(args.workflows, encoding="utf-8") as f:
        data = json.load(f)

    report = build_report(data.get("workflows", []), args.workflows)

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    html_content = render_html_report(report)
    with open(args.html_out, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Analyzed {report['total_workflows']} workflow(s)")
    print(f"  Workflows with issues: {report['workflows_with_issues']}")
    print(f"  By severity: {report['summary_by_severity']}")
    print(f"JSON report: {args.json_out}")
    print(f"HTML report: {args.html_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
