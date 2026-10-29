# TODO

Open work, roughly in priority order. Status as of v0.5.1.

## 1. Approvals that survive updates

Items cred writes (policy approvals, refreshed values) are tied to the exact build that wrote
them, so after every install each resource is blocked until its policy is approved again
(`install.sh` runs `cred policy approve` to make that one Touch ID). Without an Apple Developer
Team ID, macOS doesn't tie them to the signing identity.

- Try creating items with an explicit access list (`SecAccessCreate` +
  `SecTrustedApplicationCreateFromPath` for /usr/local/bin/cred, set via `kSecAttrAccess`), so
  the trusted app is recorded by designated requirement, as "Always Allow" does. Check whether
  the item's partition list still pins the build (cdhash) and whether that can be changed.
- Alternative: sign with an Apple Developer ID (Team ID). That would also allow the data
  protection keychain with access control, i.e. Touch ID on the items themselves.
- Done when: install a new build, and approved policies still read as approved, with no prompt.

## 2. Audit log

An append-only record of every agent action: time, site, tool, method and URL (masked),
decision (allowed, asked → yes/no, blocked). Never values. Consider chaining entries with an
HMAC whose key is in the Keychain so edits show.

## 3. Idle timeouts

- Close an idle browser after N minutes; cap a session's total length.
- Let consent (`agent.consent = "session"`) expire after a time, not only when the MCP server
  disconnects.

## 4. OS sandbox around the browser

Run the runner and Chromium under a `sandbox-exec` profile: no writes outside a private temp
dir, no reading the home folder beyond what the browser needs.

## 5. Supply chain of the browser

- The runner uses the user's Node (mise, user-writable) and Playwright's Chromium from
  `~/Library/Caches/ms-playwright` (user-writable). Pin both: check the Chromium binary's hash
  at start, or install Node and the browser root-owned next to the runner.

## 7. Sessions (rest of design step 2)

- Encrypted session vault: capture the browser's updated cookies/storage on `browse_close` and
  store them encrypted (key in the Keychain), so sessions the site rotates aren't lost.

## 8. Small things

- `cred info` and `cred ls`: show browse and fetch rules from the approved policy.
- Policy `edit`: show a diff against the approved version before approving.
- Run the end-to-end tests (`e2e`) from the repo instead of ad-hoc scripts.
