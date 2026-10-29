# TODO

Open work, roughly in priority order. Status as of v0.5.1.

## 1. Boxes (priority)

Isolated, encrypted workspaces where agents can do any work (search and read the web, run code,
keep files) but can't get out. Design: [box-design.md](box-design.md).

- Each box is a Linux VM (Apple `container`) whose only way out is a door in cred: allowed sites,
  cred's tools, model calls. No credentials enter the box; the Keychain stays the only secret
  store.
- Data lives in an AES-256 store keyed from the Keychain; `cred box rm` deletes the key.
- Covers the former items "OS sandbox around the browser", "supply chain of the browser" and the
  encrypted session vault, and parts of the audit log and idle timeouts (for boxes).
- Decisions are settled (end of the design). Phase 0 spikes 1–5 passed (results in the design):
  a VM with no network reaches cred only through a published socket; Claude Code runs on the
  subscription through the door with only a stand-in inside; stores, Chromium and Docker work
  in VMs. Next: phase 1 (spike 6, Secure Enclave keys, only matters for phase 4).
- The runner on the Mac runs Chromium without its sandbox today: Playwright adds
  `--no-sandbox` unless `chromiumSandbox: true` is passed to `chromium.launch`. Fix that now.
- Done when: phases 1–3 of the design pass their "Done when" tests.

## 2. Approvals that survive updates

Items cred writes (policy approvals, refreshed values) are tied to the exact build that wrote
them, so after every install each resource is blocked until its policy is approved again
(`install.sh` runs `cred policy approve` to make that one Touch ID). Without an Apple Developer
Team ID, macOS doesn't tie them to the signing identity. Boxes make this more pressing: each box
key would need one Keychain prompt after every update.

- Try creating items with an explicit access list (`SecAccessCreate` +
  `SecTrustedApplicationCreateFromPath` for /usr/local/bin/cred, set via `kSecAttrAccess`), so
  the trusted app is recorded by designated requirement, as "Always Allow" does. Check whether
  the item's partition list still pins the build (cdhash) and whether that can be changed.
- Alternative: sign with an Apple Developer ID (Team ID). That would also allow the data
  protection keychain with access control, i.e. Touch ID on the items themselves.
- Done when: install a new build, and approved policies still read as approved, with no prompt.

## 3. Audit log and idle timeouts in boxes

`cred mcp` on the host has both (branch `integrate-todo`). Boxes still need them: the smart
door's log (design phase 2), and `idle` and `max` limits, lock when the screen locks or the Mac
sleeps (design phase 4).

## 4. Review and verify (agent work from 2026-10-29)

Done on branch `integrate-todo` (worktree `../cred-integrate`), not yet on `main`: audit log and
`cred audit`, consent and browser time limits, `info`/`ls` policy rules, the `policy edit` diff,
repo e2e tests, SPA click waits, compact/ref snapshots, `browse_find`, `browse_requests`,
blocked writes in `cred info`, `browse_fill_credential`, Firefox and Chrome cookie sources.
Build, clippy and tests are clean (33 unit, 10 e2e, plus the browser e2e); none of it has run
against the real Keychain.

- Review the branch and merge it to `main` (the TODO there drops the items above; take this
  file's version).
- Run `mise run e2e-opt-in` once: it needs one Touch ID for a throwaway `e2e-touchid-*` resource
  and should remove it afterwards; check no `cred:e2e-touchid-*` item is left.
- Audit log: the key `cred:_audit/hmac` is made on the first audited call; check that it is
  created and read without surprises after an install (likely one Keychain prompt per new build,
  see item 2). Chaining across several `cred mcp` processes at once is untested. A network error
  on an allowed fetch is logged as `blocked`.
- Audit HMAC is hand-written over `sha2` (checked against RFC 4231); consider the `hmac` crate.
- Browser idle/max timeouts haven't run with a real browser.
- `policy edit`'s "Approve it now?" prompt needs a TTY and has no test. Approvals made before this
  build store no policy text, so they show no diff until approved again.
- `browse_fill_credential`: no Touch ID per fill, the approved policy is the only gate, and
  `fill` accepts wildcard origins (`https://*.example.com`). Decide whether either should be
  tighter. `fill_command` (src/browse.rs) has no unit test.
- Chrome cookie source: reading the "Chrome Safe Storage" password is untested (it prompts).
- Blocked-write records (`~/.config/cred/blocked-writes/`) aren't locked; concurrent `cred mcp`
  servers can lose an update.
- A click that changes nothing now costs the 3 s SPA wait.
