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

Boxes (in progress) run agents in VMs made by Apple's [`container`](https://github.com/apple/container/releases) (macOS 26). If it's installed and running (`container system start`), `install.sh` also builds the agent image from `box/agent.Containerfile`; without it the rest of cred works as before. `mise run e2e-box` tests the VM engine against a real VM.

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
cred policy edit github                      # write the policy (template on first use)
cred policy approve github                   # Touch ID; until then the policy has no effect
cred policy approve                          # all policies, one Touch ID (install.sh runs this)
cred run -s github -- gh api user            # if the policy allows: exported fields as env vars
cred ls                                      # one row per resource — never values
cred info github                             # fields, policy, expiry, refresh
cred check                                   # expired / expiring within 14 days
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

[refresh.token]
run = "~/.config/cred/refresh/app.sh"          # prints a fresh value

[agent]
consent = "session"                            # Touch ID before an agent session first uses it

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

- `cred policy approve` prints the policy and pins its sha256, and each refresh script's, in the Keychain. If the policy or a script changes afterwards, or the approval wasn't written by cred, the resource is blocked until you approve again.
- Refresh scripts get the fields that aren't exported (login, session) as `CRED_<FIELD>`. They run from a private copy of the approved bytes.
- A field refreshes in the last 5 minutes before its exact expiry, on its expiry date if only the date is known, or daily if its expiry is unknown. This happens before `cred run` or an agent uses it, and during `cred check`. JWT values get their exact expiry from the token.
- `from` handles logins only a browser can do (Google sign-in, other SSO): sign in on the site in Firefox, and cred reads the session it keeps. Firefox only for now (default profile; `CRED_FIREFOX_PROFILE` overrides).

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

Results are masked: the resource's values, and anything shaped like a JWT. Writes follow the policy's `writes` rule. When the policy asks for consent, a site's first use in a session needs your Touch ID.

## Browsing

For sites an agent should use the way a person does, add a `[browse]` section. cred starts a headless Chromium (one per site, profile in memory only), puts the session into it from stored fields, and lets the agent steer it with `browse_open`, `browse_goto`, `browse_snapshot`, `browse_click`, `browse_type`, `browse_press`, `browse_back`, `browse_screenshot` (if the policy allows it) and `browse_close`. The agent gets the page's accessibility tree with element refs, masked. It never gets the login, cookies, storage, request headers, or a way to run JavaScript.

```toml
[browse]
origins = ["https://app.example.com"]          # the only sites pages may be opened from
requests = ["https://api.example.com"]         # further hosts the pages may call or load from
writes = "ask"                                 # requests other than GET from pages: deny | ask | allow
allow_writes = ["https://app.example.com/api/telemetry"]   # URL prefixes allowed without asking
start = "https://app.example.com/home"
screenshots = true                             # let the agent see the page as an image (can't be masked)
cookies = [{ name = "session", field = "token", domain = ".example.com" }]
local_storage = [{ origin = "https://app.example.com", key = "jwt", field = "token" }]
```

Sites can be exact (`https://app.example.com`), a domain with its subdomains (`https://*.example.com`), or `"*"` for any https site. Requests to other hosts are blocked, service workers are off, and downloads are refused. Cookies only go to the domain the policy names. The runner (`runner/`, pinned `playwright-core`) is installed root-owned by `install.sh`; it uses Playwright's Chromium headless shell from `~/Library/Caches/ms-playwright`.

A `browse_open` waits for your Touch ID when the site's first use in a session needs consent, so it can take as long as you take to answer.

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

Metadata (never values) is kept in `~/.config/cred/index.json`; `CRED_INDEX` overrides it, and `CRED_POLICY_DIR` the policy folder. `CRED_WARN_DAYS` sets the warning window.
