# n8nSleuth

Export workflows from an n8n instance and scan them for common security issues. n8nSleuth is a lightweight Python toolkit with two scripts: one to pull workflows via the n8n Public API, and one to analyze the export and produce JSON and HTML reports.

## Features

- **Workflow export** — Paginated fetch of all workflows from your n8n instance, with optional filters (active status, name, tags, project).
- **Security analysis** — Static analysis of exported workflow JSON for hardcoded secrets, risky node configurations, and unsafe patterns.
- **Reports** — Machine-readable JSON summary plus a searchable HTML dashboard with severity breakdowns.

## Requirements

- Python 3.10+
- An n8n instance with the [Public API](https://docs.n8n.io/api/) enabled
- An n8n API key with permission to list workflows

## Installation

```bash
git clone https://github.com/bkbirla/n8nSleuth.git
cd n8nSleuth
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root (or pass values via CLI flags):

```env
N8N_BASE_URL=https://n8n.example.com
N8N_API_KEY=your-api-key-here
```

The `.env` file is gitignored. Do not commit API keys or exported workflow data.

## Usage

### 1. Export workflows

```bash
python export_workflows.py
```

This writes `workflows.json` in the project directory by default.

**Common options:**

| Flag | Description |
|------|-------------|
| `--url` | n8n base URL (overrides `N8N_BASE_URL`) |
| `--api-key` | API key (overrides `N8N_API_KEY`) |
| `-o`, `--output` | Output file path (default: `workflows.json`) |
| `--active true\|false` | Filter by active status |
| `--name` | Partial name match |
| `--tags` | Comma-separated tag filter |
| `--project-id` | Filter by project ID |
| `--exclude-pinned-data` | Omit pinned test data from export |
| `--limit` | Page size for API requests, max 250 (default: 250) |

Example with filters:

```bash
python export_workflows.py --active true --name "customer" -o active-customer.json
```

### 2. Analyze security

```bash
python analyze_security.py
```

Reads `workflows.json` by default and produces:

- `security_report.json` — structured findings for automation or CI
- `security_report.html` — interactive report with search and expand/collapse

**Options:**

| Flag | Description |
|------|-------------|
| `--workflows` | Path to exported workflows JSON |
| `--json-out` | JSON report output path |
| `--html-out` | HTML report output path |

Example:

```bash
python analyze_security.py --workflows active-customer.json --html-out report.html
```

### End-to-end

```bash
python export_workflows.py && python analyze_security.py
open security_report.html   # macOS; use your browser on other platforms
```

## Security checks

The analyzer flags issues across four severity levels: **critical**, **high**, **medium**, and **low**.

| Category | Examples |
|----------|----------|
| Hardcoded credentials | Bearer tokens, JWTs, OpenAI/AWS/Slack/GitHub/GitLab keys, secrets in auth headers or sensitive fields |
| Webhook exposure | Unauthenticated webhooks (escalated to critical when the workflow is active), GET webhooks without a response node, CORS `allowedOrigins: *` |
| Transport & TLS | Cleartext HTTP to non-local hosts, SSL certificate verification disabled |
| Code & execution | Dangerous patterns in Code nodes (`eval`, `child_process`, `process.env`), Execute Command nodes, SSH command nodes |
| Data & injection | SQL expressions interpolated into query strings, secrets in URL query parameters |
| Embedded data | Secrets in pinned or static workflow data |
| Supply chain | Third-party / community node types |

n8n expressions (e.g. `={{ $json.field }}`, `$credentials`, `$vars`) are treated as dynamic references and are not flagged as hardcoded secrets.

## Output files

These files are generated locally and listed in `.gitignore`:

| File | Produced by | Purpose |
|------|-------------|---------|
| `workflows.json` | `export_workflows.py` | Full workflow export from n8n |
| `security_report.json` | `analyze_security.py` | Findings summary and per-workflow details |
| `security_report.html` | `analyze_security.py` | Human-readable report |

## Project structure

```
n8nSleuth/
├── export_workflows.py   # Fetch workflows from n8n Public API
├── analyze_security.py   # Scan exports and generate reports
├── requirements.txt
├── .env                  # Your credentials (not committed)
└── README.md
```

## Limitations

- Analysis is **static** — it inspects exported JSON only and does not execute workflows.
- Findings are heuristic; review each item in context before treating it as a confirmed vulnerability.
- Requires API access to the n8n instance; it does not connect to individual node credentials stores beyond what appears in workflow definitions.

## License

MIT
