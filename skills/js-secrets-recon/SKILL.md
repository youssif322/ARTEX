---
name: js-secrets-recon
description: "Invoke this skill when the task is authorized analysis of a target's JavaScript for security-relevant intelligence beyond endpoint harvesting: hardcoded secrets and credentials, source map exposure, client-side authorization and feature-flag logic, debug and backdoor endpoints, and internal host or subdomain intel. Complements api-recon, which maps the API surface; this skill mines the harvested bundles for what should never have shipped."
---

# JS Secrets & Intelligence Recon

api-recon answers "what does the frontend call?". This skill answers "what did
the frontend leak?". It runs on the bundles api-recon already harvested
(`OUTDIR/js/`) or on freshly fetched bundles, and produces findings the
endpoint map cannot: shipped secrets, readable source maps, client-side
enforcement that hints at server-side gaps, and internal infrastructure names.

Attribution: methodology grounded in OWASP WSTG (configuration/data-exposure
testing), public secret-scanning corpora (trufflehog/gitleaks pattern sets),
and PayloadsAllTheThings (MIT).

## Boundaries

- Authorized targets only. Bundles from in-scope origins — nothing scraped
  from third parties beyond the engagement's declared asset scope.
- Secret verification is **identity-probe only**: one read-only call that
  returns *who* the key belongs to (e.g. cloud STS get-caller-identity style)
  when the engagement rules allow it. Never use a found key to read data,
  escalate, or access any third-party system beyond the provider's identity
  endpoint; when in doubt, report unverified with the pattern evidence.
- Evidence redaction: report the first 4-6 chars + length + provider class,
  never the full secret in facts or reports.
- Bundle reading discipline inherited from api-recon: >100KB files are never
  Read into context — grep with `head`/`-m` limits only.
- No brute-forcing of partial secrets (guessing the rest of a truncated key).

## Phase 0: acquire bundles

- [ ] If api-recon already ran: reuse `OUTDIR/js/` and `chunkmap.txt`;
      jump to Phase 2.
- [ ] Otherwise fetch the entry HTML, resolve script tags + webpack/Vite
      manifests + lazy chunks into a local `js/` dir; record origin of every
      file.
- [ ] Also grab: inline `<script>` blocks, `*.worker.js`, service workers,
      and any JS referenced from HTML comments or sitemaps.

## Phase 1: inventory and fingerprint

- [ ] Framework/build fingerprints (webpack_, vite, `__NEXT_DATA__`,
      angular `.js` chunks, React Native web) — decides where interesting
      artifacts live.
- [ ] Build artifacts inventory: `.map` files, `manifest.json`,
      `stats.json`, `asset-manifest.json`, `*.LICENSE.txt`.
- [ ] Note bundle count/sizes as facts (feeds coverage: unanalyzed chunks
      are a gap, not a shrug).

## Phase 2: secret pattern sweep

Families to grep (case-insensitive, both quote styles, assignment and
JSON-key forms):

- [ ] Cloud: `AKIA[0-9A-Z]{16}` (AWS), `ASIA[0-9A-Z]{16}` (temp),
      `AIza[0-9A-Za-z_-]{35}` (Google), connection strings
      (`DefaultEndpointsProtocol`, `AccountName`).
- [ ] SaaS tokens: Slack (`xox[abprs]`), Stripe (`sk_live_`, `pk_live_`),
      Twilio, SendGrid (`SG.`), GitHub (old `ghp_` format families),
      generic `Bearer ` literals.
- [ ] JWTs: `eyJ[A-Za-z0-9_-]{10,}\.eyJ` — decode header/payload only;
      never paste signatures into reports.
- [ ] Private keys/certs: `BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY`,
      `BEGIN CERTIFICATE`.
- [ ] Generic assignments: `api[_-]?key`, `secret`, `passwd`, `password`,
      `token`, `auth`, `credential` near a string literal with length ≥ 12 —
      triage by context (test/mock constants vs real-looking).
- [ ] High-entropy strings: hex/base64 runs ≥ 32 chars in config-like
      objects; triage false positives (hashes, i18n strings, img hashes).
- [ ] For every hit: record file, chunk group (which feature loads it),
      and redacted excerpt. Mark each as `verified-identity` /
      `likely-live` / `test-constant` / `false-positive`.

## Phase 3: source maps

- [ ] Check `//# sourceMappingURL=` directives and probe sibling `.map`
      paths (`chunk.js.map`, appending `.map`) at low rate.
- [ ] On a hit: map exposes original sources — file paths, developer
      comments, internal hostnames, sometimes unstripped logic. Read the
      `sources` list first, then pull only the interesting originals.
- [ ] The finding: production ships readable source maps. The intel inside
      (internal names, comments) are supporting facts, not separate findings.

## Phase 4: client-side logic and hidden features

- [ ] Authorization hints: role/permission checks, `isAdmin`, feature
      flags, `hasRole(`, route guards — each is a server-side enforcement
      test lead (feed as facts for BOLA/BFLA intents), not a finding alone.
- [ ] Debug/backdoor endpoints: `/debug`, `/internal`, `/test`, `/admin`,
      `console`, `impersonate` in path literals — candidates for the
      fuzzing-methodology skill.
- [ ] Commented-out or conditional code: disabled features, staging URLs,
      TODO/FIXME/HACK/XXX markers near security-sensitive calls.
- [ ] Third-party integrations: analytics keys, Sentry DSNs, monitoring
      endpoints — map the external surface (report as posture intel).
- [ ] Crypto usage: hardcoded IVs, ECB mode, weak custom obfuscation,
      `obfuscator.io` patterns — each is a finding candidate or a hint the
      real logic is server-side.

## Phase 5: infrastructure intel

- [ ] Internal hostnames/IPs: `grep` for RFC1918 literals, `internal.`,
      `corp.`, `staging.`, `dev.`, `preprod`, port numbers in URL literals —
      each in-scope name becomes an asset-graph lead (insert_assets or fact).
- [ ] Subdomain intel: hostnames in API bases, WebSocket URLs, image CDN
      prefixes; feeds subdomain enumeration cross-checks.
- [ ] CORS/config endpoints: `Access-Control` literals, `/config.json`,
      `/env.js` style bootstrap files fetched before login — fetch and
      analyze those directly.

## Phase 6: evidence and reporting

- [ ] Every secret finding: provider class, redacted value, location
      (file + chunk), verification status, and the impact statement (what
      the key could do, stated — not demonstrated).
- [ ] Source-map finding: map URL + `sources` count + 2-3 example original
      file paths as proof.
- [ ] Internal-host intel: listed as facts tied to assets; not findings
      unless they prove an exposed internal surface.
- [ ] Bundle coverage statement: how many chunks analyzed vs total.

## Tools

| Tool | Use | Notes |
|---|---|---|
| api-recon scripts (`harvest_static.py`) | bundle acquisition | preferred path when both skills run |
| grep/ripgrep recipes | pattern sweep | head/-m limits mandatory |
| jwt decode (custom tool) | JWT header/payload read | signature never reported |
| entropy triage (custom tool) | high-entropy candidates | interpreters are human-gated; package as custom tool |

## Completion self-check

- [ ] every secret has redacted evidence and a verification status.
- [ ] no secret was used beyond a single identity probe (if allowed at all).
- [ ] source maps checked on every bundle with sourceMappingURL or .map
      sibling.
- [ ] internal names fed into facts/assets, not left buried in the trace.
- [ ] no >100KB file was pulled into conversation context.
