#!/usr/bin/env python3
"""Export all workflows from an n8n instance to a single JSON file."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

from dotenv import load_dotenv


DEFAULT_LIMIT = 250
DEFAULT_OUTPUT = "workflows.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch all workflows from an n8n instance via the Public API."
    )
    parser.add_argument(
        "--url",
        default=None,
        help="n8n instance base URL (env: N8N_BASE_URL). Example: https://n8n.example.com",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="n8n API key (env: N8N_API_KEY). Sent as X-N8N-API-KEY header.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Output file path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--active",
        choices=("true", "false"),
        help="Filter by active status.",
    )
    parser.add_argument(
        "--name",
        help="Filter by workflow name (partial match).",
    )
    parser.add_argument(
        "--tags",
        help="Comma-separated tag names to filter by.",
    )
    parser.add_argument(
        "--project-id",
        help="Filter workflows by project ID.",
    )
    parser.add_argument(
        "--exclude-pinned-data",
        action="store_true",
        help="Omit pinned test data from each workflow.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Page size for API requests, max 250 (default: {DEFAULT_LIMIT}).",
    )
    args = parser.parse_args()

    if args.url is None:
        args.url = os.environ.get("N8N_BASE_URL")
    if args.api_key is None:
        args.api_key = os.environ.get("N8N_API_KEY")

    return args


def normalize_base_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError("Base URL must start with http:// or https://")
    return url


def build_query_params(args: argparse.Namespace) -> dict[str, str]:
    params: dict[str, str] = {"limit": str(min(max(args.limit, 1), 250))}

    if args.active is not None:
        params["active"] = args.active
    if args.name:
        params["name"] = args.name
    if args.tags:
        params["tags"] = args.tags
    if args.project_id:
        params["projectId"] = args.project_id
    if args.exclude_pinned_data:
        params["excludePinnedData"] = "true"

    return params


def sanitize_for_json(value: Any) -> Any:
    """Replace lone UTF-16 surrogates so output is valid UTF-8 JSON."""
    if isinstance(value, str):
        return "".join(
            char if not (0xD800 <= ord(char) <= 0xDFFF) else "\ufffd" for char in value
        )
    if isinstance(value, dict):
        return {
            sanitize_for_json(key): sanitize_for_json(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_for_json(item) for item in value]
    return value


def api_request(base_url: str, api_key: str, path: str, params: dict[str, str]) -> dict[str, Any]:
    query = urlencode(params)
    url = urljoin(f"{base_url}/", path.lstrip("/"))
    if query:
        url = f"{url}?{query}"

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "X-N8N-API-KEY": api_key,
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=60) as response:
            payload = response.read().decode("utf-8")
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from n8n API: {body or exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Failed to reach n8n instance: {exc.reason}") from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError("n8n API returned invalid JSON") from exc


def fetch_all_workflows(base_url: str, api_key: str, params: dict[str, str]) -> list[dict[str, Any]]:
    workflows: list[dict[str, Any]] = []
    cursor: str | None = None

    while True:
        page_params = dict(params)
        if cursor:
            page_params["cursor"] = cursor

        response = api_request(base_url, api_key, "/api/v1/workflows", page_params)
        page = response.get("data")
        if page is None:
            raise RuntimeError("Unexpected API response: missing 'data' field")

        if not isinstance(page, list):
            raise RuntimeError("Unexpected API response: 'data' is not a list")

        workflows.extend(page)
        cursor = response.get("nextCursor")
        if not cursor:
            break

    return workflows


def main() -> int:
    load_dotenv(Path(__file__).resolve().parent / ".env")
    args = parse_args()

    if not args.url:
        print("Error: provide --url or set N8N_BASE_URL in .env.", file=sys.stderr)
        return 1
    if not args.api_key:
        print("Error: provide --api-key or set N8N_API_KEY in .env.", file=sys.stderr)
        return 1

    try:
        base_url = normalize_base_url(args.url)
        params = build_query_params(args)
        workflows = fetch_all_workflows(base_url, args.api_key, params)
    except (RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    export_payload = sanitize_for_json(
        {
            "exportedAt": datetime.now(timezone.utc).isoformat(),
            "n8nInstance": base_url,
            "workflowCount": len(workflows),
            "workflows": workflows,
        }
    )

    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(export_payload, output_file, indent=2, ensure_ascii=False)
        output_file.write("\n")

    print(f"Exported {len(workflows)} workflow(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
