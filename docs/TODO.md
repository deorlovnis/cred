# TODO

Open work, roughly in priority order. Status as of v0.5.1.

## 1. Boxes (priority)

Isolated, encrypted workspaces where agents can do any work (search and read the web, run code,
keep files) but can't get out. Design: `docs/box-design.md` (local notes, not published).

- Each box is a Linux VM (Apple `container`) whose only way out is a door in cred: allowed sites,
  cred's tools, model calls. No credentials enter the box; the Keychain stays the only secret
  store.
- Data lives in an AES-256 store keyed from the Keychain; `cred box rm` deletes the key.
- Covers the former items "OS sandbox around the browser", "supply chain of the browser" and the
  encrypted session vault, and parts of the audit log and idle timeouts (for boxes).
- Phases 0–2 are built and passed their "Done when" checks on a real install (2026-10-29;
  results in the design). Open from phase 2: WebSockets through the door; the log-head check
  live (next install). Phase 3 (one browser VM per box, sealed sessions, `cred box login`,
  downloads kept on the Mac) is built and passes its tests on real VMs; the live run on a real
  install is next. Then phase 4 (hardening).
- Done when: phases 1–3 of the design pass their "Done when" tests.

## 2. Boxes and the Mac: code in, work out, recovery, the IDE

Technical task, open for discussion: the options below are a starting point, not a decision;
better ideas are welcome.

**Today.** A `clone` mount copies the folder into the box's `work/` once, on the first run,
file by file (links and special files skipped). After that nothing flows either way, except
`cred box export` (a file or folder out, Touch ID) and `cred box import` (into `work/`, box
stopped). The store is kept, encrypted, and Time Machine backs it up encrypted.

**Problems.**
- The copy takes everything: `.git`, dependencies, build output, and local secret files such as
  `.env.local`. A secret file in a repo ends up readable by the agent, against "the Keychain is
  the only secret store". Big folders make the first run slow.
- The agent's work has no easy way back to the Mac repo other than export by hand.
- No way back if the agent wrecks its own copy (`rm -rf`, a bad rebase), short of Time Machine.
- IDEs (IntelliJ in particular) can't see the box: Claude Code's IDE plugin talks to the CLI over
  a local socket the box can't reach, and the agent edits the box copy, not the Mac's.

**Constraints.** Whatever leaves the box is untrusted: the agent could plant files that run when
opened on the Mac (git hooks, IDE run configurations, Gradle or npm scripts, `.envrc`). No
decrypted copy of the store should sit on the Mac without the user asking for it. The door stays
the only way out.

**Options.**
1. Git-aware clone: when the folder is a git repo, copy what git would (tracked files, plus new
   files not ignored, keeping the branch and uncommitted changes); leave out ignored files
   (`.env*`, `node_modules`, build output). Possibly an `exclude = [...]` in `[[mount]]` for
   non-git folders, and a warning listing secret-looking files that would be copied.
2. Git sync out: each cloned repo gets a remote `mac`, served by the door, that lands in a bare
   repo on the Mac (`~/Library/Application Support/cred/sync/<box>/<repo>.git`); pushed by the
   agent, or by cred when the box stops. The person runs `git fetch box` in their real repo and
   reviews the agent's branches. A bare repo runs nothing it receives. Open: committed work only,
   or also a WIP commit of uncommitted changes at stop; whether the door should check refs or sizes.
3. Plain one-way mirror of `work/` to a Mac folder (rsync-like, at stop or periodically). Simple,
   covers uncommitted work and non-git files, but leaves a decrypted copy on the Mac and the
   planted-file risk; would need a dedicated cred folder, never the original repo.
4. Snapshots for recovery: `cred box snapshot` plus one automatically at stop, keeping the last N
   encrypted copies of the store (or APFS snapshots inside it); `cred box restore NAME [WHEN]`.
5. Host to box refresh: bring new commits from the Mac repo into the box copy (`git fetch` from a
   read-only mount of the Mac repo), so long-lived boxes don't drift.
6. IDE:
   - Run `cred box run` in the IDE's terminal (works today; no plugin integration).
   - Review the agent's branches in the IDE through the git sync (option 2).
   - Bridge Claude Code's IDE connection (diffs, selection, diagnostics) through the door: opens a
     channel from the agent into the IDE, and paths differ between box and Mac.
   - JetBrains Gateway / remote development with the IDE backend in the box: needs a connection
     into the VM, a large backend and more memory.

**Leaning:** 1, then 2, then 4, with the IDE through 2; 3 only if git-based sync proves too
narrow. To decide before building.

- Done when: agreed on a design here, then: a repo with a `.env.local` clones into a box without
  it; the agent's commits show up in the Mac repo after `git fetch box`; a wrecked `work/` can be
  restored; the chosen IDE workflow works with IntelliJ.

## 3. Approvals that survive updates

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

## 4. Audit log and idle timeouts in boxes

`cred mcp` on the host has both. Boxes still need them: the smart
door's log (design phase 2), and `idle` and `max` limits, lock when the screen locks or the Mac
sleeps (design phase 4).

## 5. Review and verify (agent work from 2026-10-29)

Merged to `main` on 2026-10-29: audit log and
`cred audit`, consent and browser time limits, `info`/`ls` policy rules, the `policy edit` diff,
repo e2e tests, SPA click waits, compact/ref snapshots, `browse_find`, `browse_requests`,
blocked writes in `cred info`, `browse_fill_credential`, Firefox and Chrome cookie sources.
Build, clippy and tests are clean (33 unit, 10 e2e, plus the browser e2e); none of it has run
against the real Keychain.

- Run `mise run e2e-opt-in` once: it needs one Touch ID for a throwaway `e2e-touchid-*` resource
  and should remove it afterwards; check no `cred:e2e-touchid-*` item is left.
- Audit log: the key `cred:_audit/hmac` is made on the first audited call; check that it is
  created and read without surprises after an install (likely one Keychain prompt per new build,
  see item 3). Chaining across several `cred mcp` processes at once is untested. A network error
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
