# Offensive tuning: full automation inside an authorized scope

How to run ARTEX at full depth and full automation for an authorized
engagement — using the guard system the way it was designed, not against it.
Everything here is configuration; nothing requires a rebuild.

Companion skills: `xss-exploitation`, `sqli-deep`, `ssrf-exploitation`,
`js-secrets-recon`, `fuzzing-methodology` (see `skills/`).

## 1. Scope first

The target gate is what makes full automation safe enough to enable. Before
opening any throttle below:

1. Declare the engagement's companies/assets (root domains, IPs, URLs) in the
   UI so the target gate can validate every tool call against them.
2. Keep third-party hosts you never want touched (analytics, CDNs, payment
   providers) out of scope — out-of-scope asset intercept rules can block them
   explicitly (`EvaluateAssetGate` applies block rules before allow rules).
3. With a correct scope, the rules below cannot leak a request outside the
   authorized perimeter.

## 2. Guard rules: auto-approve the scanner toolchain

Interception rules live in the UI (System → Interception) with three match
types: `string`, `regex`, and `argv`. The recommended set is argv rules —
an argv rule matches the program and subcommand prefix exactly while ignoring
flags, so `["nmap"]` approves `nmap -sV -p 1-1000 target` without approving
anything else.

Suggested argv allow rules for a standard engagement:

| Rule pattern | Effect |
|---|---|
| `["nmap"]` | port/service scanning incl. NSE |
| `["nuclei"]` | template scanning |
| `["ffuf"]` | content/param fuzzing |
| `["httpx"]` | HTTP probing |
| `["katana"]` | crawling |
| `["dalfox"]` | XSS automation |
| `["sqlmap"]` | SQLi automation (see note) |
| `["subfinder", "-all"]` | passive subdomain enum |
| `["gobuster"]` | directory brute force |
| `["wafw00f"]` | WAF fingerprinting |
| `["whatweb"]` | tech fingerprinting |
| `["testssl.sh"]` | TLS checks |

Notes:

- **Denylist is final by design**: argv allow rules can never cover shells,
  interpreters (`python`, `bash`, `node`, …), launchers (`sudo`, `xargs`,
  `docker`, …), or destructive programs (`rm`, `mkfs`, …). Those still need a
  human decision. This is the platform's authorization fabric — do not try to
  bypass it with a `string` rule like `^python`; keep interpreter work as
  custom tools (below) or approve it manually.
- **sqlmap**: prefer an argv rule plus task-level boundaries over running it
  wrapped in a shell one-liner; the sqli-deep skill pins `--batch` and
  threads.
- **Faster path while warming up**: when a pending call appears, use
  *Always allow* in the approval dialog — it derives the argv rule from the
  exact command that was about to run (mirrors
  `POST /api/intercept/pending/{id}/always-allow`).

## 3. Budgets: let tasks run deep

In the task/agent configuration:

- Raise **token and turn budgets** for long exploration chains (a deep SQLi
  or SSRF chain legitimately consumes hundreds of turns).
- Keep a per-intent budget so one runaway intent cannot starve the task.
- If the provider supports it, enable `llm_rotate` so worker failover does not
  end a long task on a single provider hiccup.

## 4. Noise profile: match the environment

- **Staging / internal lab**: no noise profile (default) — scanners run at
  their own pace.
- **Production, authorized**: set the noise profile so agents receive the
  low-and-slow prompt block with exact rate flags for the bundled scanners;
  combine with `-rate`/`-t` flags inside custom tools for hard capping.
- The skills (`sqli-deep`, `ssrf-exploitation`) already encode restraint
  rules (time-probe lengths, port-probe budgets) that respect the profile.

## 5. Custom tools for interpreter-shaped work

Because interpreters stay behind the human gate, package recurring
interpreter work as **custom tools** (System → Tools): the execution spec is
stored encrypted in PostgreSQL and exposed to agents as first-class tools
with their own schemas. A custom tool named `lfi-check` running a pinned
python script is approvable as one unit, and its target extraction goes
through the same target gate.

## 6. MCP servers

Remote tools register under System → MCP (http or sse transport). This fork
ships two read-only intelligence servers under `mcp/` (Kali deployment guide
in `mcp/README.md`): `nuclei-templates` (template search/selection) and
`seclists-lookup` (tiered wordlist recommendations). Skills can declare
`mcps:` in their frontmatter so the tools unlock only when the skill is
loaded (`fuzzing-methodology` does).

## Checklist for an unleashed-but-scoped engagement

- [ ] assets and block rules reflect the contract, third parties excluded
- [ ] argv allow rules created for the scanner toolchain
- [ ] budgets raised at task level, kept per-intent
- [ ] noise profile chosen per environment
- [ ] recurring interpreter work moved to custom tools
- [ ] worker traces on (default) so evidence binding captures everything
