---
name: sqli-deep
description: "Invoke this skill when the task is authorized offensive testing for SQL injection beyond automated scanning: manual detection across injection points (params, headers, cookies, JSON, XML), UNION/error/boolean/time/out-of-band techniques, DBMS fingerprinting, sqlmap tuning and tamper selection against WAFs, second-order injection, and minimal-footprint extraction proofs."
---

# Deep SQL Injection Testing

Automated scanners find the loud injections; this skill finds and proves the
quiet ones — odd injection points, filtered front-ends, second-order storage —
and extracts the minimum needed to make the finding undeniable.

Attribution: methodology grounded in the OWASP WSTG, the PortSwigger SQL
injection materials, PayloadsAllTheThings (MIT), and the sqlmap wiki.

## Boundaries

- Read-only posture by default: `SELECT`-class proofs (`version()`,
  `current_user`, row counts, a single authorized row). No `DROP`, `DELETE`,
  `UPDATE`, `INSERT`, `SHUTDOWN`, or privilege changes on live data.
- Extraction minimization: prove read access with version/user/one row — do
  not dump tables. The finding is the injection, not the dataset.
- OS-file read (`LOAD_FILE`, `pg_read_file`) only when the engagement's rules
  explicitly allow it, and only paths named in those rules.
- Time-based probing stays gentle: short sleeps (2-5s), few iterations, never
  against a production peak window if the noise profile forbids it.
- sqlmap batch runs use `--batch`, explicit `--threads` (default 3), and an
  explicit `--timeout`; no `--risk 3 --level 5` reflex-fire without a targeted
  reason.

## Phase 1: injection point discovery

- [ ] Params are the obvious case — cover the rest: `X-Forwarded-For`,
      `User-Agent`, `Referer`, `Cookie` values, JSON keys (incl. keys inside
      nested objects), XML tags, `ORDER BY` / sort / column-name parameters,
      `LIMIT`/offset values, table or field selectors in APIs.
- [ ] Structured inputs: break the structure deliberately (`{"a": 1'}`,
  unterminated strings in XML) and diff the error response.
- [ ] Second-order candidates: values stored now and interpolated into a
  query later (registration username rendered in an admin page, address
  printed on an invoice query).

## Phase 2: detection primitives

- [ ] Error signatures — feed `'` `"` `\`)` and fingerprint from the message:
      MySQL (`You have an error in your SQL syntax`), PostgreSQL
      (`ERROR: unterminated quoted string` / `pg_`), MSSQL (`Unclosed quotation
      mark after`), Oracle (`ORA-01756`), SQLite (`SQLITE_ERROR` / `unrecognized
      token`).
- [ ] Boolean differential: `AND 1=1` vs `AND 1=2` — diff status, length, and
      body hash; also `OR 1=1` on expected-empty results.
- [ ] Time-based where blind: `AND SLEEP(3)` / `pg_sleep(3)` /
      `WAITFOR DELAY '0:0:3'`; confirm with a control request first (baseline
      latency), twice, both directions.
- [ ] UNION scaffolding: `ORDER BY n` bisection for column count, then
      NULL-fill and find string columns (`'a'` substitution) for the echo.
- [ ] Out-of-band (fully blind): DNS/HTTP beacon probes
      (`LOAD_FILE(CONCAT(...))` / `UTL_HTTP` / `xp_dirtree`) toward the
      engagement listener only.

## Phase 3: DBMS fingerprint and version

- [ ] Version functions per DBMS: `@@version`, `version()`, `sqlite_version()`,
      `v$version` — even a failed attempt's error shape narrows the DBMS.
- [ ] Concatenation syntax as a tiebreaker: `||` vs `CONCAT()`, comment styles
      (`--` vs `#` vs `/* */`), quote handling for identifiers.

## Phase 4: manual exploitation depth

- [ ] UNION extraction: enumerate information_schema / pg_catalog /
      `INFORMATION_SCHEMA.TABLES` (MSSQL/SQLite share the name) — list table
      names, then columns of the one relevant table, then a single row.
- [ ] Error-based channels when errors echo: `EXTRACTVALUE`/`UPDATEXML`
      (MySQL), cast-to-int (Postgres), conversion errors (MSSQL).
- [ ] Stacked queries only where the driver allows (MSSQL, some MySQL/PHP
      configs) — and only with read statements under the boundaries above.
- [ ] Blind binary-search extraction: script it (positional `SUBSTRING` +
      `ASCII` comparisons), keep request counts in the tens, log each probe to
      the task dir as evidence of methodology.

## Phase 5: sqlmap when automation helps

- [ ] Feed the exact injection point (`-p`, `--headers`, cookie params,
      `*` marker inside `--url` for non-param positions), never bare URL
      crawling when the point is already known.
- [ ] `--technique=` to scope (e.g. `BT` for a blind+time target),
      `--level`/`--risk` raised one step at a time with a reason recorded.
- [ ] Tamper selection by observed filter, not by popularity: e.g.
      `space2comment` (space filtering), `between` (keyword `>`), `charencode`
      (case-sensitive WAF), `randomcase` (signature WAFs) — record which one
      worked and why.
- [ ] Authenticated runs: pass the session (`--cookie`/`--headers`/`--data`)
      through the recording proxy so evidence is captured.
- [ ] Second-order: `--second-url` pointing at the consuming page.
- [ ] Never `--os-shell`/`--os-pwn` on live targets; file write/read flags
      only inside the engagement rules.

## Phase 6: WAF and filter evasion (manual layer)

- [ ] Whitespace alternatives: `/**/`, `%09`/`%0a`/`%0d`, parentheses packing.
- [ ] Keyword case/randomization, inline comments `UN/**/ION`, `SEL/*x*/ECT`.
- [ ] Operator substitution: `=` via `LIKE`/`BETWEEN`/`REGEXP`, `OR` via `||`.
- [ ] Encoding: URL double-encode, unicode-IIS (`%u0027`) where applicable,
      hex literals (`0x6162`) for strings.
- [ ] Each bypass attempt and its response goes into the trace facts — the
      WAF fingerprint itself is a reportable observation.

## Phase 7: evidence and closure

- [ ] Bind to the finding: the exact differential request pair (or the
      time-based control + probe pair), the DBMS+version proof, and the single
      authorized row or version output.
- [ ] Record request counts used — restraint is part of the report.
- [ ] Any failed cleanup of temp rows (sqlmap tables, etc.) reported honestly.

## Tools

| Tool | Use | Notes |
|---|---|---|
| sqlmap | automated exploitation | bundled; always `--batch`, threads pinned |
| curl | differential probes | pair every probe with a control |
| ffuf + param wordlists | injection point discovery | low rate, marker words |
| jq | JSON response diffing | for API boolean oracles |

## Completion self-check

- [ ] every finding carries the request/response differential and the DBMS
      proof.
- [ ] no write-class statement ran against live data.
- [ ] extraction stayed at version/user/one-row depth.
- [ ] sqlmap runs logged with flags used and tamper rationale.
