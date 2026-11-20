#!/usr/bin/env python3
"""ARTEX MCP server: SecLists wordlist intelligence.

Curated, tiered wordlist recommendations plus read-only inspection, so agents
choose the right list per target instead of grabbing the biggest file. Lookup
only — ffuf execution stays with ARTEX's guarded Bash tools.

Deploy (Kali):
    sudo apt install seclists            # /usr/share/seclists
    ~/mcp-venv/bin/python mcp/seclists-lookup/server.py

Register in ARTEX (System -> MCP, http transport):
    http://<this-host>:8902/mcp

Env overrides: ARTEX_MCP_HOST, ARTEX_MCP_PORT, SECLISTS_DIR
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

HOST = os.environ.get("ARTEX_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("ARTEX_MCP_PORT", "8902"))

CANDIDATE_ROOTS = [
    os.environ.get("SECLISTS_DIR", ""),
    "/usr/share/seclists",
    str(Path.home() / "SecLists"),
]
MAX_PREVIEW = 100

# Curated use-case table mirroring the fuzzing-methodology skill's tiers.
# Paths are relative to the SecLists root; entries missing on this install
# are reported as such (Kali's package lags the upstream repo sometimes).
RECOMMENDATIONS: dict[str, list[tuple[str, str]]] = {
    "directory": [
        ("Discovery/Web-Content/common.txt", "tier 1 — always first pass"),
        ("Discovery/Web-Content/raft-small-directories.txt", "tier 2 — small"),
        ("Discovery/Web-Content/raft-medium-directories.txt", "tier 2 — medium"),
        ("Discovery/Web-Content/directory-list-2.3-small.txt", "tier 3 — deep, small"),
        ("Discovery/Web-Content/directory-list-2.3-medium.txt", "tier 3 — deep, medium"),
    ],
    "files": [
        ("Discovery/Web-Content/common.txt", "shared first pass"),
        ("Discovery/Web-Content/raft-small-files.txt", "small file names"),
        ("Discovery/Web-Content/raft-medium-files.txt", "medium file names"),
        ("Discovery/Web-Content/big.txt", "when the surface justifies it"),
    ],
    "extensions": [
        ("Discovery/Web-Content/web-extensions.txt", "suffix pass on found dirs"),
        ("Discovery/Web-Content/raft-medium-words.txt", "as extension bodies on IIS/Apache"),
    ],
    "api": [
        ("Discovery/Web-Content/api/api-endpoints.txt", "generic API endpoints"),
        ("Discovery/Web-Content/api/api-paths.txt", "API paths"),
        ("Discovery/Web-Content/swagger.txt", "swagger/OpenAPI paths"),
    ],
    "params": [
        ("Discovery/Web-Content/burp-parameter-names.txt", "hidden param mining"),
    ],
    "vhosts": [
        ("Discovery/DNS/subdomains-top1million-5000.txt", "quick vhost pass"),
        ("Discovery/DNS/namelist.txt", "larger vhost pass"),
    ],
    "subdomains": [
        ("Discovery/DNS/subdomains-top1million-5000.txt", "quick tier"),
        ("Discovery/DNS/subdomains-top1million-110000.txt", "standard active enum"),
    ],
    "tech": [
        ("Discovery/Web-Content/Apache.fuzz.txt", "Apache-specific paths"),
        ("Discovery/Web-Content/IIS.fuzz.txt", "IIS-specific paths"),
        ("Discovery/Web-Content/nginx.txt", "nginx-specific paths"),
        ("Discovery/Web-Content/spring-boot.txt", "Spring Boot actuators"),
        ("Discovery/Web-Content/tomcat.txt", "Tomcat paths"),
    ],
    "payloads-xss": [
        ("Payloads/XSS/polyglots.txt", "XSS polyglots"),
        ("Payloads/XSS/xss-vectors.txt", "XSS vectors"),
    ],
    "payloads-sqli": [
        ("Payloads/SQL-injection-FUZZDB/MD5.txt", "FUZZDB SQLi set (sample)"),
        ("Fuzzing/SQLi.txt", "generic SQLi fuzz payloads"),
    ],
    "backup-files": [
        ("Discovery/Web-Content/quickhits.txt", "known juicy files one-shot"),
        ("Discovery/Web-Content/Logins.txt", "login pages"),
    ],
}

mcp = FastMCP("seclists-lookup", host=HOST, port=PORT)


def _root() -> Path | None:
    for r in CANDIDATE_ROOTS:
        if r and Path(r).is_dir():
            return Path(r).resolve()
    return None


def _jail(rel: str) -> Path | None:
    """Resolve rel under the SecLists root, refusing traversal outside it."""
    root = _root()
    if root is None:
        return None
    full = (root / rel).resolve()
    if full != root and root not in full.parents:
        return None
    return full


def _stats(path: Path) -> dict:
    size = path.stat().st_size
    lines = 0
    with path.open("rb") as fh:
        for _ in fh:
            lines += 1
    return {"bytes": size, "lines": lines}


@mcp.tool()
def status() -> str:
    """Report the SecLists root and its top-level families."""
    root = _root()
    if root is None:
        return json.dumps({
            "ok": False,
            "error": "SecLists not found; apt install seclists or set SECLISTS_DIR",
            "checked": [r for r in CANDIDATE_ROOTS if r],
        })
    families = sorted(p.name for p in root.iterdir() if p.is_dir())
    return json.dumps({"ok": True, "root": str(root), "families": families})


@mcp.tool()
def recommend(use_case: str) -> str:
    """Tiered wordlist recommendations for a use case, with install status and
    size. Cases: directory, files, extensions, api, params, vhosts,
    subdomains, tech, payloads-xss, payloads-sqli, backup-files."""
    table = RECOMMENDATIONS.get(use_case.lower().strip())
    if table is None:
        return json.dumps({
            "ok": False,
            "use_cases": sorted(RECOMMENDATIONS),
            "hint": "unknown use case; call with one of the listed values",
        })
    out = []
    for rel, note in table:
        full = _jail(rel)
        if full and full.is_file():
            entry = {"path": rel, "note": note, "installed": True, **_stats(full)}
        else:
            entry = {"path": rel, "note": note, "installed": False}
        out.append(entry)
    return json.dumps({"ok": True, "use_case": use_case, "recommendations": out})


@mcp.tool()
def browse(family: str, subpath: str = "") -> str:
    """List a SecLists subdirectory (e.g. browse('Discovery/Web-Content')).
    Returns dirs and file stats so an agent can explore beyond the curated
    table without shell access."""
    rel = f"{family}/{subpath}" if subpath else family
    full = _jail(rel)
    if full is None or not full.is_dir():
        return json.dumps({"ok": False, "error": "path outside SecLists root or not a dir"})
    dirs, files = [], []
    for p in sorted(full.iterdir()):
        if p.is_dir():
            dirs.append(p.name)
        elif p.is_file():
            files.append({"name": p.name, "bytes": p.stat().st_size})
    return json.dumps({"ok": True, "path": rel, "dirs": dirs[:80], "files": files[:200]})


@mcp.tool()
def preview(path: str, offset: int = 0, count: int = 20) -> str:
    """Preview lines of a wordlist (paginated, capped at 100 per call)."""
    full = _jail(path)
    if full is None or not full.is_file():
        return json.dumps({"ok": False, "error": "path outside SecLists root or missing"})
    count = max(1, min(count, MAX_PREVIEW))
    with full.open(errors="ignore") as fh:
        for _ in range(max(0, offset)):
            next(fh, None)
        lines = [next(fh, None) for _ in range(count)]
    return json.dumps({
        "ok": True,
        "path": path,
        "offset": offset,
        "lines": [l.rstrip("\n") for l in lines if l is not None],
    })


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
