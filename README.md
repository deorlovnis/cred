# cred

Keychain-backed secrets for humans and agents on macOS. Values live only in the login Keychain. Agents never get them: they work through `cred mcp`, where cred makes the requests and adds the credentials itself.

Secrets are grouped by **resource**, one thing you sign in to (`github`, `aws`, `app`). A resource has a link, a description and **fields** (`token`, `user`, `password`, `session`, …), each its own Keychain item. What may happen to them is decided by the resource's **policy**, which has no effect until you approve it with Touch ID.

## Install

Requires macOS, Rust (`mise use -g rust@stable`, or rustup), and Node.js for the sandboxed browser.

```sh
git clone https://github.com/deorlovnis/cred.git ~/Git/cred
~/Git/cred/install.sh        # builds, signs, installs /usr/local/bin/cred and the browser runner (root-owned)
cred --help
```

To update: `git pull && ./install.sh`. It ends by asking you to approve your policies again, with one Touch ID (see Signing). Never install a debug build: debug builds let tests answer approval prompts.

### Signing

macOS asks before an app reads a Keychain item it didn't store, and remembers **Always Allow** per app identity. A plain Rust build is ad-hoc signed, so every rebuild counts as a new app and asks again. Sign with a stable self-signed identity once, and your Always Allow answers survive updates:

```sh
cat > /tmp/cred-cert.cnf <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = cred code signing
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
CNF
cd "$(mktemp -d)"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -config /tmp/cred-cert.cnf -keyout key.pem -out cert.pem
openssl pkcs12 -export -inkey key.pem -in cert.pem -name "cred code signing" -out cred.p12 -passout pass:tmp \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1   # algorithms the Keychain can import
security import cred.p12 -k ~/Library/Keychains/login.keychain-db -P tmp   # no -T: signing must ask
rm -f key.pem cert.pem cred.p12 /tmp/cred-cert.cnf
```

When `codesign` asks to use the key, choose **Allow**, never **Always Allow**: a key anything can use silently lets any program running as you sign a lookalike cred that the Keychain trusts. After switching identities, run `cred reseal` so each item trusts only the new cred, then approve your policies again.

Items cred writes itself, policy approvals included, stay tied to the exact build that wrote them: without an Apple Developer Team ID, macOS can't tie them to the signing identity. Approvals are read without allowing a prompt, so after an update they read as missing and every resource is blocked until you approve again. `install.sh` does that at the end. Keychain prompts take your login password; Touch ID only appears in cred's own approval prompts.

## Use

```sh
cred set github token --expires 2027-01-31   # hidden prompt; asks for link/description
cred update github token                     # rotate: copy the new token, run this
cred policy edit github                      # write the policy; shows a diff against the approved one
cred policy approve github                   # Touch ID; until then the policy has no effect
cred policy approve                          # all policies, one Touch ID (install.sh runs this)
cred run -s github -- gh api user            # if the policy allows: exported fields as env vars
cred ls                                      # one row per resource, with a summary of its policy
cred info github                             # fields, expiry, refresh, and what the approved policy allows
cred check                                   # expired / expiring within 14 days
cred audit                                   # what agents did through cred mcp (never values)
```

`cred copy RES FIELD` asks for Touch ID. `cred describe RES` edits the link and description, and `cred rm RES [FIELD]` deletes. Put resource names (one per line) in a `.cred` file in a repo and `cred run -- CMD` loads them. `cred --help` lists everything.

## Policies

`~/.config/cred/policy/<resource>.toml`:

```toml
[run]
mode = "ask"                                   # cred run: allow | ask (Touch ID each time) | deny
export = { token = "APP_TOKEN" }               # fields cred run exports, as env vars

[refresh.session]
from = "firefox:https://app.example.com#session_token"   # read from Firefox Local Storage
                                               # (or firefox-cookie:… / chrome-cookie:… for a cookie)

[refresh.token]
run = "~/.config/cred/refresh/app.sh"          # prints a fresh value

[agent]
consent = "session"                            # Touch ID before an agent session first uses it
consent_minutes = 240                          # ...and again after this long (0: only after a reconnect)

[fetch]
hosts = ["https://api.example.com"]            # the only hosts cred sends credentials to
writes = "deny"                                # requests other than GET/HEAD: deny | ask | allow
auth = "Bearer {token}"                        # header cred adds; the agent never sees it
auth_header = "Authorization"                  # the default
headers = { "x-client-id" = "web" }            # fixed, non-secret headers the site expects

[[tool]]
name = "item"
about = "Get one item"
request = "GET https://api.example.com/items/{id}"
```

- `cred ls` and `cred info` show what the *approved* policy allows. In `ls`, `run:ask fetch browse:ask` means `cred run` asks, requests are allowed (writes denied), and pages may send writes after asking: a mode after a colon is the rule for writes, or for `cred run`. A policy that isn't approved, or changed since, shows as such instead, and none of it applies.
- `cred policy edit` shows what your edit changed compared to the approved version (a colored diff in a terminal) and offers to approve it.
- `cred policy approve` prints the policy and pins its sha256, and each refresh script's, in the Keychain. If the policy or a script changes afterwards, or the approval wasn't written by cred, the resource is blocked until you approve again.
- Refresh scripts get the fields that aren't exported (login, session) as `CRED_<FIELD>`. They run from a private copy of the approved bytes.
- A field refreshes in the last 5 minutes before its exact expiry, on its expiry date if only the date is known, or daily if its expiry is unknown. This happens before `cred run` or an agent uses it, and during `cred check`. JWT values get their exact expiry from the token.
- `from` handles logins only a browser can do (Google sign-in, other SSO): sign in on the site in a browser, and cred reads the session it keeps. `firefox:ORIGIN#KEY` reads a Local Storage key, `firefox-cookie:ORIGIN#NAME` a cookie from Firefox (default profile; `CRED_FIREFOX_PROFILE` overrides), and `chrome-cookie:ORIGIN#NAME` a cookie from Chrome's Default profile (`CRED_CHROME_PROFILE` overrides). Chrome encrypts its cookies with a key kept in the Keychain as "Chrome Safe Storage", so macOS asks for your login password the first time cred reads it (Always Allow stops that).

## Agents

Register once:

```sh
claude mcp add --scope user cred -- /usr/local/bin/cred mcp
```

The agent gets these tools:
- `sites`: lists what each approved site allows.
- `fetch(site, method, url, body)`: a request to one of the site's hosts. cred adds the credentials and doesn't follow redirects.
- One tool per `[[tool]]` in the policies.
- The `browse_*` tools, for sites whose policy has a `[browse]` section (see Browsing).

Results are masked: the resource's values, and anything shaped like a JWT. Writes follow the policy's `writes` rule. When the policy asks for consent, a site's first use in a session needs your Touch ID. The consent lapses after `consent_minutes` (default 240; 0 keeps it until the agent disconnects), and the next use asks again.

### Audit log

Every call an agent makes through `cred mcp` is appended to `~/.config/cred/audit.log` once it has run, before the agent gets the result. If the log can't be opened or written (say, its Keychain key is unreadable), the agent gets an error instead. One JSON line per call: time, site, tool, method, URL and decision: `allowed`, `asked:yes` or `asked:no` (you were asked, and answered), or `blocked` (refused by the policy, or failed before an answer). Never values, headers, bodies or typed text. URLs are masked like everything else the agent sees, and lose any user, password and `#fragment`; query values that look like secrets (keys like `token`, `key`, `code`, or long opaque strings) and opaque path segments become `********`.

Each line carries an HMAC over its content and the previous line's, keyed by an item in the Keychain (`cred:_audit/hmac`, created on first use). `cred audit` shows the latest entries (`-n 50` for more); `cred audit --verify` reads the whole log and reports the first line where the chain breaks, so an edited, swapped or removed line shows. Cutting lines off the end can't be seen. Same-user limit: whoever can read the key from the Keychain (a program running as you, with your approval of a prompt) could forge a chain.

## Browsing

For sites an agent should use the way a person does, add a `[browse]` section. cred starts a headless Chromium (one per site, profile in memory only), puts the session into it from stored fields, and lets the agent steer it with `browse_open`, `browse_goto`, `browse_snapshot`, `browse_find`, `browse_click`, `browse_type`, `browse_press`, `browse_back`, `browse_requests`, `browse_screenshot` (if the policy allows it), `browse_fill_credential` (if the policy lists fields) and `browse_close`. The agent gets the page's accessibility tree with element refs, masked. It never gets the login, cookies, storage, request headers, or a way to run JavaScript.

- Pages can be large: `browse_snapshot` takes `compact` (one short line per named element) or `ref` (just that element), and `browse_find(text)` returns only the elements whose name or text match, with their refs.
- After a click (or Enter), cred waits up to 3 seconds for the URL or the page's text to change, so single-page apps return the new view.
- `browse_requests` lists the data requests (XHR/fetch: method and URL, never headers or bodies; query values over 16 characters left out) the pages made, so the agent can find the API behind a view and use `fetch` instead of scraping.
- `browse_fill_credential(ref, field)` types a stored field into an input, for sites without a session to inject. cred does it itself, only for fields the policy lists in `fill`, and only when the page and the input's frame are on the policy's origins. The typed value is masked in everything returned.

```toml
[browse]
origins = ["https://app.example.com"]          # the only sites pages may be opened from
requests = ["https://api.example.com"]         # further hosts the pages may call or load from
writes = "ask"                                 # requests other than GET from pages: deny | ask | allow
allow_writes = ["https://app.example.com/api/telemetry"]   # URL prefixes allowed without asking
fill = ["user", "password"]                    # fields browse_fill_credential may type (not with origins = "*")
start = "https://app.example.com/home"
screenshots = true                             # let the agent see the page as an image (can't be masked)
idle_minutes = 10                              # the browser closes after this long without a call (0: never)
max_minutes = 60                               # ...and this long after it opened, however busy (0: never)
cookies = [{ name = "session", field = "token", domain = ".example.com" }]
local_storage = [{ origin = "https://app.example.com", key = "jwt", field = "token" }]
```

Sites can be exact (`https://app.example.com`), a domain with its subdomains (`https://*.example.com`), or `"*"` for any https site. Requests to other hosts are blocked, service workers are off, and downloads are refused. Cookies only go to the domain the policy names. The runner (`runner/`, pinned `playwright-core`) is installed root-owned by `install.sh`; it uses Playwright's Chromium headless shell from `~/Library/Caches/ms-playwright`.

Writes that pages try without an `allow_writes` rule (a telemetry POST on every page load, say) are blocked or asked about, and remembered without their query or body: `cred info SITE` lists them, so you can add the harmless ones to `allow_writes`. The page tools mention this when a write was blocked.

A browser closes by itself after `idle_minutes` without a call, and `max_minutes` after it opened; the agent then needs `browse_open` again. A `browse_open` waits for your Touch ID when the site's first use in a session needs consent, so it can take as long as you take to answer.

## Boxes

A **box** is an isolated, encrypted place where an agent works: a Linux VM with no network of its own, whose only way out is a door cred keeps. The agent can do any work a person at a computer could (run code, install packages, keep files) but can't see your Mac, your Keychain or any credential. What it keeps is in an AES-256 store whose key lives in the Keychain; deleting the key destroys the box. Phase 1 (this section) covers boxes that reach listed sites; the open web with read-only rules, and the browser inside the box, come later.

```sh
cred box new research              # policy template in $EDITOR, a new key in the Keychain, an empty store
cred box approve research          # Touch ID; until then the box can't open
cred box run research              # Touch ID opens it; you're in Claude Code, inside the box
cred box run research -- bash      # a shell in the same box (joins it if it's running)
cred box run --temp research       # a throwaway box with research's policy, gone when it stops
cred box ls                        # open or locked, policy status, size, sites, last used
cred box log research              # what went through the door
cred box export research work/report.md --to ~/Desktop   # Touch ID; lists each file with size and sha256
cred box import research ~/data.csv                      # copy a file or folder into work/ (box stopped)
cred box stop research             # stop and lock; also happens when `run` ends or on Ctrl-C
cred box rm research               # Touch ID; deletes the key, then the store
```

`cred policy approve` with no names approves your boxes too, so `install.sh` still needs one Touch ID.

`~/.config/cred/box/<name>.toml` (`CRED_BOX_DIR` overrides the folder):

```toml
about = "Market research"
run = ["claude"]                        # what `cred box run` starts; `-- CMD` replaces it
image = "cred-agent@sha256:..."         # the system inside, pinned by digest: a new image is a policy change
model = "anthropic"                     # resource whose key cred adds to the agent's model calls
sites = ["github", "app"]               # resources the agent may use through cred; their policies apply
keep = true                             # false: a new store every run, shredded when it stops, key never kept
cpus = 4
memory = "8G"
# docker = true                         # Docker Engine inside the box

[net]
allow = ["https://*.wikipedia.org", "https://docs.rs"]   # the only sites the agent's own requests reach; "*" = any public https site

[[mount]]                               # holes in the box: none unless listed
path = "~/Git/project"
mode = "clone"                          # clone: the agent works on its own copy in work/ | ro: read-only at /mnt/project
```

- A box policy works like a resource policy: no effect until approved, a change blocks the box until approved again, and `cred box edit` shows a diff against the approved version. The approval is kept under the Keychain name `box.NAME` (resource names can't contain a dot, so it never collides with a resource).
- One Touch ID at `run` opens the box and covers consent for its `sites`. Their own policies still decide hosts, writes and what may be browsed. `model` names a resource with a `[fetch]` policy: cred forwards the agent's model calls to its host with the real key, and the agent only has a stand-in. Joining a running box (`run NAME -- CMD` from another terminal) asks nothing more.
- **Phase 1 limits.** The door sees host names, not requests: an allowed site gets whatever the agent sends it, so list sites you trust. `[net] writes` and `allow_writes` belong to phase 2 and `[browser]` to phase 3; the policy is refused if it sets them, rather than promising rules the door can't keep. `rw` mounts aren't offered: files come in with `clone` or `import` and go out with `export`.
- Mounts: `clone` copies the folder (with its `.git`) into the box's `work/` on the first run, and the agent keeps its own copy after. `ro` mounts the folder itself read-only. Folders that hold cred's own files, your home folder and `/` are refused.
- Inside, `/home/agent`, `/work` and `/downloads` are folders of the store; `/tmp` is memory. The agent starts in `/work`. On each run cred makes sure Claude Code's settings skip the web-fetch check and know cred's tools (`cred-shim mcp`), keeping anything else the agent put in those files.
- The store is an APFS sparse bundle in `~/Library/Application Support/cred/box/`, opened with the key on `hdiutil`'s stdin into a private folder, hidden from Finder and Spotlight, and only while the box runs. A store never shrinks when files are deleted (`hdiutil compact` doesn't work on APFS images).
- `export`, `import` and `rm` need the box stopped, because cred doesn't touch a folder a VM has mounted (and a running agent could swap a link in the folder while it is read). `export` copies regular files only, never follows links, and logs each file in the box's log. `log` reads an open box without asking.
- `cred box rm` warns that Time Machine may still hold encrypted copies of the store; restored together with a Keychain from before the removal, which has the old key, they would open.
- A crash leaves an attached store or a throwaway store behind; the next `run` or `stop` detaches and deletes them.

## What cred protects, and what it doesn't

- **Protected:** values never reach the agent through cred. They stay in the Keychain, are added to requests by cred, are masked in everything cred returns, and refresh scripts run from approved bytes. Nothing loosens a policy or releases a value without Touch ID.
- **Not protected:** whatever the agent reads (API responses, page text, screenshots) is in its context, and the agent's client may store it. Claude Code keeps tool results, screenshots included, in its session folder under `~/.claude/projects/`. Masking can't reach text inside a screenshot, so leave `screenshots` off for sites whose pages show secrets.
- **Same-user limits:** the agent runs as you. It can't read values silently, but it can cause Keychain or Touch ID prompts. Approve only prompts you expect.

## With Claude Code

Deny direct Keychain and clipboard reads in `~/.claude/settings.json` too:

```json
{ "permissions": { "deny": [
  "Bash(security find-generic-password:*)",
  "Bash(security find-internet-password:*)",
  "Bash(security dump-keychain:*)",
  "Bash(security export:*)",
  "Bash(cred copy:*)",
  "Bash(pbpaste:*)"
] } }
```

Metadata (never values) is kept in `~/.config/cred/index.json`; `CRED_INDEX` overrides it, and `CRED_POLICY_DIR` the policy folder, `CRED_BOX_DIR` the box policy folder. `CRED_WARN_DAYS` sets the warning window.

## Development

```sh
mise run e2e         # end-to-end tests: the built binary, a local test site, `cred run` and `cred mcp`
mise run e2e-opt-in  # also the sandboxed browser, and one real Touch ID approval (you tap)
```

`cargo test` runs the unit tests and the same end-to-end tests. Debug builds keep Keychain items in a temp folder when `CRED_TEST_KEYCHAIN` is set and take `CRED_TEST_APPROVE=yes|no` as the Touch ID answer, so those tests need no human and never touch your Keychain; release builds contain neither. The opt-in tests are `#[ignore]`d: the browser one needs `npm ci` in `runner/` and Playwright's Chromium (`install.sh` fetches it), and the Touch ID one uses the real Keychain with a throwaway resource name and removes it afterwards.
