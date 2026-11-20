---
name: fuzzing-methodology
description: "Invoke this skill when the task is authorized dictionary-driven discovery on a mapped target: directory and file brute force, API path discovery, hidden parameter mining, virtual host and subdomain enumeration, and backup/config file hunting — with wordlist selection by technology, ffuf tuning, calibration against false positives, and noise-budgeted execution. Not for payload-level injection testing (see sqli-deep / xss-exploitation)."
---

# Fuzzing Methodology (Content, Params, Hosts)

Fuzzing finds what links don't. The difference between a noisy, useless run
and a high-yield one is three decisions made before any request: the right
wordlist, the right calibration, the right rate. This skill encodes those
decisions.

Attribution: methodology grounded in OWASP WSTG, the ffuf wiki, SecLists
structure (MIT), and public wordlist-strategy guides ( PayloadsAllTheThings,
MIT).

## Boundaries

- All requests through the engagement budget: thread counts and rates follow
  the task's noise profile (staging: default; production: low-and-slow flags
  pinned).
- Canary-first: every fuzz run starts with a calibration request (random
  nonexistent name) to learn the soft-404 shape — no calibration, no run.
- No auth-lockout pressure: one 401/403-shape per target; wordlists aimed at
  authenticated guesses (usernames/passwords) are out of scope here.
- Destructive-path awareness: exclude `logout|delete|destroy|reset` style
  patterns when the target state matters (same exclusion list api-recon uses).
- Every discovered path worth reporting gets verified once by hand (curl)
  before becoming a fact.

## Phase 1: fingerprint before fuzzing

- [ ] Server/tech fingerprint: `whatweb`/`wafw00f`/response headers — the
      tech decides the extension and wordlist family.
- [ ] Response-shape learning: capture 200/403/404/soft-404 responses for
      the root; note any WAF block page (rate + signature).
- [ ] Decide scope of the fuzz: dirs, files, extensions, params, vhosts,
      subdomains — record which and why.

## Phase 2: wordlist selection (the core decision)

Escalate by tier; small lists first, deep lists only when the tier above
yielded or the target clearly deserves depth:

| Tier | List (SecLists) | When |
|---|---|---|
| 1 | `Discovery/Web-Content/common.txt` | always first pass |
| 2 | `Discovery/Web-Content/raft-{small,medium}-*` | tier 1 hit or mature app |
| 3 | `Discovery/Web-Content/directory-list-2.3-{small,medium}.txt` | deep dive on big attack surface |
| tech | `Discovery/Web-Content/{IIS,Apache,NGINX}*.txt`, `CMS/*` | fingerprint says so |
| ext | `Discovery/Web-Content/web-extensions.txt` + `.bak .old .swp .save .copy .orig .gz .tar .zip` | file hunting |
| api | `Api/` lists + `Discovery/Web-Content/api/` endpoints | API-surface targets (with api-recon output) |
| params | `burp-parameter-names.txt` | parameter mining |
| vhosts | `Discovery/DNS/*/subdomains-*.txt` | vhost enum |

- [ ] Extension strategy by tech: `.php` (php), `.aspx/.asp` (IIS),
      `.jsp/do/action` (java), `.html/.js` (static/SPA); only relevant
      extension sets — never all extensions on all targets.

## Phase 3: ffuf tuned correctly

| Flag | Value | Why |
|---|---|---|
| `-w` | tiered list (Phase 2) | — |
| `-t` | noise profile: staging 40, production 5-10 | budget |
| `-rate` | set when profile says so | hard cap |
| `-mc all -fc 404` or `-mc 200,204,301,302,307,401,403` | — | catch interesting non-200s |
| `-fs <canary-size>` / `-fw`/`-fl` | from calibration | kills soft-404 farms |
| `-recursion -recursion-depth 2` | dirs | depth 3+ rarely pays |
| `-replay-proxy http://127.0.0.1:8788` | ARTEX recording proxy | evidence binding for hits |
| `-o json -od` | output | facts + dedupe |
| `-of json` with `-od <dir>` | per-target files | merge into task dir |

- [ ] Calibration: one request to a random 16-char name; record status,
      size, words — these become the `-fs`/`-fw` filters. Soft-404s that
      mimic 200s are the #1 false-positive source.
- [ ] On WAF signs (429/403 wall): drop threads, add small jitter —
      or conclude and report the WAF behavior itself.

## Phase 4: content discovery passes

- [ ] Directory pass (tiered) → note redirects and where they point.
- [ ] File + extension pass on discovered dirs: configs
      (`*.config`, `web.config`, `.env*`), backups (`.bak/.old/.swp/.gz`),
      exports (`*.sql`, `*.dump`), editor droppings (`.DS_Store`,
      `Thumbs.db`), git exposure (`/.git/HEAD` probe → if hit, the repo
      leak is the finding; do not pull the whole repo without scope check).
- [ ] Verify each hit manually once: curl the URL, confirm content class
      (real page vs parked redirect vs error), then write fact.

## Phase 5: hidden parameter mining

- [ ] Reflected/behavioral params: `arjun`-style multi-location probing
      (GET, then POST forms, then JSON) — package as custom tool since
      interpreters are human-gated.
- [ ] ffuf param fuzz: `?FUZZ=1` with param wordlist + `-fs` calibration;
      diff against no-param baseline.
- [ ] Interesting-by-name params first: `debug, test, admin, internal,
      user, role, redirect, url, callback, file, path, template, lang`.
- [ ] Feed confirmed params to the attack skills (sqli-deep,
      xss-exploitation, ssrf-exploitation) as facts.

## Phase 6: vhost and subdomain enumeration

- [ ] Passive subdomains first: `subfinder -all` (argv-allow rule exists) —
      zero traffic to target.
- [ ] Active DNS resolution only on the passive set + a DNS wordlist tier;
      confirmed names become asset-graph subdomains.
- [ ] Vhost fuzzing: `ffuf -w vhosts -H "Host: FUZZ.target" ` against the
      IP with `-fs` calibrated on the default vhost response; every
      size-deviant vhost is a new origin to fingerprint.
- [ ] Wildcard-DNS check before trusting resolution hits (random name
      resolving = wildcard).

## Phase 7: API path brute force

- [ ] With api-recon's endpoint list as *known*, fuzz for the *unknown*:
      api wordlists under discovered prefixes.
- [ ] Verb-aware probing: OPTIONS first, then GET; note 405s (endpoint
      exists, wrong verb) — a 405 is a fact worth an intent.
- [ ] kiterunner-style verb+path combos only on targets the fingerprint
      suggests (.NET/Java heavy APIs).

## Phase 8: triage into the graphs

- [ ] Discovered endpoints/paths → `insert_assets` (endpoint nodes) — never
      leave findings only in the trace.
- [ ] Discovered params → facts anchored to their endpoint assets.
- [ ] Discovered vhosts/subdomains → asset nodes with source "fuzz".
- [ ] Report the WAF/rate behavior observed as environment facts (helps the
      next intents choose rates).

## Tools

| Tool | Use | Notes |
|---|---|---|
| ffuf | all dictionary fuzzing | argv-allow rule exists; replay into proxy |
| subfinder | passive subdomain enum | `-all`, zero target traffic |
| whatweb / wafw00f | fingerprint | argv-allow rules exist |
| curl | calibration + hit verification | paired control pattern |
| katana / spider | link discovery pre-fuzz | reduces blind fuzz area |

## Completion self-check

- [ ] every run had calibration before it (filters derived, not guessed).
- [ ] wordlist tier choice recorded with rationale per target.
- [ ] every reported path verified once by hand and inserted as asset/fact.
- [ ] thread/rate settings logged alongside the noise profile.
- [ ] no auth-lockout pressure; destructive patterns excluded.
