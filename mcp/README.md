# ARTEX MCP servers (Kali deployment)

Two read-only intelligence servers that extend ARTEX agents over MCP. They
never execute scanners and never write: actual `nuclei`/`ffuf` execution
stays with ARTEX's guarded Bash tools, keeping every action inside the
approval + target-gate fabric.

| Server | Port | Tools | Purpose |
|---|---|---|---|
| `nuclei-templates` | 8901 | `status`, `rebuild_index`, `search_templates`, `list_categories`, `get_template` | Browse/search the local nuclei template library so agents pick precise templates (severity/category/tag) instead of blind `-t all` |
| `seclists-lookup` | 8902 | `status`, `recommend`, `browse`, `preview` | Tiered wordlist recommendations per use case + paginated inspection, mirroring the `fuzzing-methodology` skill's tiers |

## Install on the Kali VM

```bash
# 1. Data sources (skip if already present)
sudo apt update && sudo apt install -y seclists      # /usr/share/seclists
nuclei -ut                                          # populate ~/nuclei-templates

# 2. Runtime (once, on the VM)
python3 -m venv ~/mcp-venv
~/mcp-venv/bin/pip install -r mcp/requirements.txt
# note: requirements pin mcp<2 — v2 renamed FastMCP with breaking changes;
# if a venv already has mcp 2.x, downgrade: pip install -U 'mcp>=1.9.0,<2'

# 3. Run
~/mcp-venv/bin/python mcp/nuclei-templates/server.py   # :8901
~/mcp-venv/bin/python mcp/seclists-lookup/server.py    # :8902
```

Sanity check before registering:

```bash
curl -s http://127.0.0.1:8901/mcp -o /dev/null -w '%{http_code}\n'  # expect 200/406
curl -s http://127.0.0.1:8902/mcp -o /dev/null -w '%{http_code}\n'
```

(406 is fine — it means the endpoint answered but wants MCP headers.)

## Register in ARTEX

System → MCP → add server, transport `http`:

| Name | URL |
|---|---|
| `nuclei-templates` | `http://<VM-IP>:8901/mcp` |
| `seclists-lookup` | `http://<VM-IP>:8902/mcp` |

Host reachability:

- ARTEX directly on the VM: `http://127.0.0.1:890x/mcp`
- ARTEX in Docker on the VM: use the VM's LAN IP, or the docker bridge
  gateway `http://172.17.0.1:890x/mcp` (servers bind `0.0.0.0` for this)
- Keep the two ports LAN-only in the VM firewall; the servers carry no auth
  by design (lab-internal services)

## Skill gating

`fuzzing-methodology` declares `mcps: ["seclists-lookup"]` in its
frontmatter, so the lookup tools unlock when that skill loads. `nuclei-templates`
is registered ungated (useful to any recon intent). The skill parser test
(`TestShippedSkillsParseCleanly`) covers the frontmatter edit.

## First-run behavior

- `nuclei-templates` builds an index of every template on first call
  (~10-30s on a VM, cached to `~/.cache/artex-mcp/nuclei-index.json`);
  call `rebuild_index` after future `nuclei -ut` updates.
- `seclists-lookup` reads `/usr/share/seclists` (Kali package) or
  `~/SecLists` (git clone); override with `SECLISTS_DIR`.
- Missing curated lists (Kali's package lags upstream sometimes) are
  reported `installed: false` instead of guessed at.

## Env overrides

| Var | Default | Meaning |
|---|---|---|
| `ARTEX_MCP_HOST` | `0.0.0.0` | bind address |
| `ARTEX_MCP_PORT` | 8901 / 8902 | bind port |
| `NUCLEI_TEMPLATES_DIR` | `~/nuclei-templates` | template root |
| `SECLISTS_DIR` | `/usr/share/seclists` | SecLists root |

## Security posture

- Read-only filesystem access, jailed to the template/SecLists roots —
  path traversal attempts are refused by `_jail()`.
- No command execution, no network egress, no writes outside the index cache.
- If you later expose the VM's MCP ports beyond the lab, front them with an
  authenticating reverse proxy instead of relying on obscurity.
