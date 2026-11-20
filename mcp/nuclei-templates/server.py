#!/usr/bin/env python3
"""ARTEX MCP server: nuclei template library intelligence.

Read-only browsing and search over the local nuclei-templates checkout, so
agents pick precise templates instead of blind `nuclei -t all` runs. Template
execution itself stays with ARTEX's guarded Bash tools — this server never
runs nuclei and never writes anything.

Deploy (Kali):
    python3 -m venv ~/mcp-venv && ~/mcp-venv/bin/pip install -r mcp/requirements.txt
    ~/mcp-venv/bin/python mcp/nuclei-templates/server.py

Register in ARTEX (System -> MCP, http transport):
    http://<this-host>:8901/mcp

Env overrides: ARTEX_MCP_HOST, ARTEX_MCP_PORT, NUCLEI_TEMPLATES_DIR
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

HOST = os.environ.get("ARTEX_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("ARTEX_MCP_PORT", "8901"))

# Where nuclei keeps its templates by default on Kali (nuclei -ut writes here).
CANDIDATE_ROOTS = [
    os.environ.get("NUCLEI_TEMPLATES_DIR", ""),
    str(Path.home() / "nuclei-templates"),
    "/root/nuclei-templates",
    "/usr/share/nuclei-templates",
]
INDEX_CACHE = Path.home() / ".cache" / "artex-mcp" / "nuclei-index.json"
MAX_TEMPLATE_BYTES = 200_000  # skip giant workflow bundles
MAX_BODY_LINES = 50

mcp = FastMCP("nuclei-templates", host=HOST, port=PORT)


def _root() -> Path | None:
    for r in CANDIDATE_ROOTS:
        if r and Path(r).is_dir():
            return Path(r).resolve()
    return None


def _jail(rel: str) -> Path | None:
    """Resolve rel under the template root, refusing traversal outside it."""
    root = _root()
    if root is None:
        return None
    full = (root / rel).resolve()
    if full != root and root not in full.parents:
        return None
    return full


def _parse_template(path: Path, root: Path) -> dict | None:
    try:
        if path.stat().st_size > MAX_TEMPLATE_BYTES:
            return None
        doc = yaml.safe_load(path.read_text(errors="ignore"))
        if not isinstance(doc, dict):
            return None
        info = doc.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        tags = str(info.get("tags", "")).replace(",", " ").split()
        return {
            "id": str(doc.get("id") or path.stem),
            "name": str(info.get("name", ""))[:160],
            "severity": str(info.get("severity", "")).lower(),
            "tags": tags,
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "category": str(path.relative_to(root).parts[0]),
        }
    except Exception:
        return None


def _build_index() -> list[dict]:
    root = _root()
    if root is None:
        return []
    entries: list[dict] = []
    for path in root.rglob("*.yaml"):
        entry = _parse_template(path, root)
        if entry:
            entries.append(entry)
    INDEX_CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"built_at": time.time(), "entries": entries}))
    tmp.replace(INDEX_CACHE)
    return entries


def _load_index(max_age_s: float = 14 * 86400) -> list[dict]:
    try:
        data = json.loads(INDEX_CACHE.read_text())
        if time.time() - data.get("built_at", 0) > max_age_s:
            return []
        return data.get("entries", [])
    except Exception:
        return []


def _indexed() -> list[dict]:
    entries = _load_index()
    if not entries:
        entries = _build_index()
    return entries


@mcp.tool()
def status() -> str:
    """Report template root, template count, and index freshness."""
    root = _root()
    if root is None:
        return json.dumps({
            "ok": False,
            "error": "nuclei-templates directory not found; set NUCLEI_TEMPLATES_DIR",
            "checked": [r for r in CANDIDATE_ROOTS if r],
        })
    entries = _indexed()
    return json.dumps({
        "ok": True,
        "root": str(root),
        "templates": len(entries),
        "index_cached": bool(_load_index()),
    })


@mcp.tool()
def rebuild_index() -> str:
    """Rebuild the template index from disk (after `nuclei -ut` updates)."""
    root = _root()
    if root is None:
        return json.dumps({"ok": False, "error": "template root not found"})
    entries = _build_index()
    return json.dumps({"ok": True, "templates": len(entries)})


@mcp.tool()
def search_templates(
    query: str = "",
    severity: str = "",
    category: str = "",
    tag: str = "",
    limit: int = 25,
) -> str:
    """Search indexed nuclei templates. All filters are optional and combine
    with AND. `query` matches id/name substring; `severity` filters
    (critical/high/medium/low/info); `category` is the top template dir
    (cves, vulnerabilities, exposed-panel, misconfiguration, ...); `tag`
    matches one tag exactly (e.g. panel, wordpress, cve2024)."""
    entries = _indexed()
    q = query.lower()
    sev = severity.lower()
    cat = category.lower()
    hits = []
    for e in entries:
        if q and q not in e["id"].lower() and q not in e["name"].lower():
            continue
        if sev and e["severity"] != sev:
            continue
        if cat and e["category"].lower() != cat:
            continue
        if tag and tag.lower() not in [t.lower() for t in e["tags"]]:
            continue
        hits.append(e)
        if len(hits) >= max(1, min(limit, 100)):
            break
    return json.dumps({"count": len(hits), "results": hits})


@mcp.tool()
def list_categories() -> str:
    """List template categories (top-level dirs) with per-category counts."""
    entries = _indexed()
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["category"]] = counts.get(e["category"], 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    return json.dumps({"categories": [{"name": c, "templates": n} for c, n in ranked]})


@mcp.tool()
def get_template(path: str) -> str:
    """Return a template's metadata and its first lines (review before use).
    `path` is the relative path returned by search_templates."""
    full = _jail(path)
    if full is None or not full.is_file():
        return json.dumps({"ok": False, "error": "path outside template root or missing"})
    entry = _parse_template(full, _root()) or {"path": path}
    try:
        body_head = "\n".join(
            full.read_text(errors="ignore").splitlines()[:MAX_BODY_LINES]
        )
    except Exception as exc:
        body_head = f"<read error: {exc}>"
    return json.dumps({"ok": True, "template": entry, "body_head": body_head})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
