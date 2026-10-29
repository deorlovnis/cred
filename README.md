# cred

Keychain-backed secrets for humans and agents on macOS. Values live only in the login Keychain. Agents never get them: they work through `cred mcp`, where cred makes the requests and adds the credentials itself.

Secrets are grouped by **resource**, one thing you sign in to (`github`, `aws`, `app`). A resource has a link, a description and **fields** (`token`, `user`, `password`, `session`, …), each its own Keychain item. What may happen to them is decided by the resource's **policy**, which has no effect until you approve it with Touch ID.

## Install

Requires macOS and Rust (`mise use -g rust@stable`, or rustup).

```sh
git clone https://github.com/deorlovnis/cred.git ~/Git/cred
~/Git/cred/install.sh        # builds, signs, installs /usr/local/bin/cred (root-owned)
cred --help
```

To update: `git pull && ./install.sh`. Never install a debug build: debug builds let tests answer approval prompts.

### Signing

macOS asks before an app reads a Keychain item it didn't store, and remembers **Always Allow** per app identity. A plain Rust build is ad-hoc signed, so every rebuild counts as a new app and asks again. Sign with a stable self-signed identity once, and approvals survive updates:

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

## Use

```sh
cred set github token --expires 2027-01-31   # hidden prompt; asks for link/description
cred update github token                     # rotate: copy the new token, run this
cred policy edit github                      # write the policy (template on first use)
cred policy approve github                   # Touch ID; until then the policy has no effect
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

[[tool]]
name = "item"
about = "Get one item"
request = "GET https://api.example.com/items/{id}"
```

- `cred policy approve` prints the policy and pins its sha256, and each refresh script's, in the Keychain. If the policy or a script changes afterwards, or the approval wasn't written by cred, the resource is blocked until you approve again.
- Refresh scripts get the fields that aren't exported (login, session) as `CRED_<FIELD>`. They run from a private copy of the approved bytes.
- A field refreshes within an hour of expiring, or daily if its expiry is unknown. This happens before `cred run` or an agent uses it, and during `cred check`. JWT values get their exact expiry from the token.
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

Results are masked: the resource's values, and anything shaped like a JWT. Writes follow the policy's `writes` rule. When the policy asks for consent, a site's first use in a session needs your Touch ID.

## Browsing

For sites an agent should use the way a person does, add a `[browse]` section. cred starts a headless Chromium (one per site, profile in memory only), puts the session into it from stored fields, and lets the agent steer it with `browse_open`, `browse_goto`, `browse_snapshot`, `browse_click`, `browse_type`, `browse_press`, `browse_back` and `browse_close`. The agent gets the page's accessibility tree with element refs, masked. It never gets the login, cookies, storage, request headers, or a way to run JavaScript.

```toml
[browse]
origins = ["https://app.example.com"]          # the only sites pages may be opened from
requests = ["https://api.example.com"]         # further hosts the pages may call or load from
writes = "ask"                                 # requests other than GET from pages: deny | ask | allow
allow_writes = ["https://app.example.com/api/telemetry"]   # URL prefixes allowed without asking
start = "https://app.example.com/home"
cookies = [{ name = "session", field = "token", domain = ".example.com" }]
local_storage = [{ origin = "https://app.example.com", key = "jwt", field = "token" }]
```

Requests to other hosts are blocked, service workers are off, and downloads are refused. The runner (`runner/`, pinned `playwright-core`) is installed root-owned by `install.sh`.

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
