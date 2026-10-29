# cred

Keychain-backed secrets for humans and agents on macOS. Values live only in the login Keychain; `cred run` injects them into a command as env vars and masks them in its output, so an agent can use a token without ever seeing it.

Secrets are grouped by **resource** — one thing you sign in to (`github`, `aws`, `app`). A resource has a link, a description and **fields** (`token`, `user`, `password`, …), each its own Keychain item. Only fields mapped to an env var are exported by `cred run`; the rest stay inside cred and are handed only to the resource's refresh command.

## Install

Requires macOS and Rust (`mise use -g rust@stable`, or rustup).

```sh
git clone https://github.com/deorlovnis/cred.git ~/Git/cred
cd ~/Git/cred
cargo install --path . --root ~/.local   # installs ~/.local/bin/cred; add --force to replace an existing one
cred --help
```

To update: `git pull && cargo install --path . --root ~/.local --force`.

The first time a new build reads a secret it didn't store itself, macOS asks for Keychain access — choose **Always Allow**.

## Use

```sh
cred set github token --env GITHUB_TOKEN --expires 2027-01-31   # hidden prompt; asks for link/description
cred update github token                     # rotate: copy the new token, run this
cred ls                                      # one row per resource — never values
cred info github                             # fields, export names, expiry, refresh
cred check                                   # expired / expiring within 14 days
cred run -s github -- gh api user            # exported fields injected, values masked
```

`cred env RES FIELD VAR` changes what a field is exported as (`--off` keeps it inside cred), `cred describe RES` edits the link/description, `cred rm RES [FIELD]` deletes. Put resource names (one per line) in a `.cred` file in a repo and `cred run -- CMD` loads them. `cred --help` lists everything.

### Auto-refresh

For short-lived tokens, store the login as fields and give cred a command that prints a fresh value. The command gets the resource's fields as `CRED_<FIELD>`:

```sh
cred set app user
cred set app password
cred auto app token --cmd ~/.config/cred/refresh/app.sh   # script uses $CRED_USER / $CRED_PASSWORD
cred env app token APP_TOKEN
cred refresh app --force                     # refresh now (without --force: only if due)
```

For logins only a browser can do (Google sign-in, other SSO), sign in there and let cred read the session the site keeps in Local Storage. The value never leaves cred:

```sh
cred auto app session --from 'firefox:https://app.example.com#session_token'
cred auto app token --cmd ~/.config/cred/refresh/app.sh   # uses $CRED_SESSION
```

Firefox only for now (default profile; `CRED_FIREFOX_PROFILE` overrides). When the session expires, sign in on the site again.

A field is refreshed within an hour of expiring (daily if its expiry is unknown) — automatically right before `cred run` uses it and during `cred check`. JWT values get their exact expiry from the token.

Metadata (never values) is kept in `~/.config/cred/index.json`; override with `CRED_INDEX`. `CRED_WARN_DAYS` sets the warning window.

## With Claude Code

Deny direct Keychain and clipboard reads in `~/.claude/settings.json` so the agent has to go through `cred run`:

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
