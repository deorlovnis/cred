# cred

Keychain-backed secrets for humans and agents on macOS. Values live only in the login Keychain; `cred run` injects them into a command as env vars and masks them in its output, so an agent can use a token without ever seeing it.

## Install

Requires macOS and Rust (`mise use -g rust@stable`, or rustup).

```sh
git clone https://github.com/deorlovnis/cred.git ~/Git/cred
cd ~/Git/cred
cargo install --path . --root ~/.local   # installs ~/.local/bin/cred; add --force to replace an existing one
cred --help
```

To update: `git pull && cargo install --path . --root ~/.local --force`.

The first time a new build reads a secret it didn't store itself, macOS asks for Keychain access — choose **Always Allow**. A rebuilt binary counts as new, so expect this once per secret after each update.

## Use

```sh
cred set GITHUB_TOKEN --expires 2027-01-31   # hidden prompt, then optional link + description
cred update GITHUB_TOKEN                     # rotate: copy the new token, run this
cred ls                                      # names, expiry, status — never values
cred check                                   # expired / expiring within 14 days
cred run -s GITHUB_TOKEN -- gh api user      # run with the secret injected and masked
```

Put names (one per line) in a `.cred` file in a repo and `cred run -- CMD` loads them. `cred --help` and `cred <command> --help` list everything.

Metadata (expiry, link, description — never values) is kept in `~/.config/cred/index.json`; override with `CRED_INDEX`. `CRED_WARN_DAYS` sets the warning window.

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
