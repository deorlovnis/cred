#!/bin/sh
# Build, sign and install cred as /usr/local/bin/cred, and its browser runner in
# /usr/local/lib/cred/runner, owned by root so nothing running as you can replace them.
#
# The signing key asks before every signing: choose "Allow", never "Always Allow". Otherwise
# any program running as you could sign a lookalike cred that the Keychain trusts. Without the
# identity the build is installed ad-hoc signed, with a warning. See README "Signing".
set -eu
cd "$(dirname "$0")"
identity="${CRED_SIGN_IDENTITY:-cred code signing}"
dest=/usr/local/bin/cred

cargo build --release
if security find-identity -p codesigning | grep -qF "\"$identity\""; then
  echo "macOS asks to use the \"$identity\" key: choose Allow, not Always Allow."
  codesign --force --sign "$identity" --identifier com.deorlovnis.cred target/release/cred
else
  echo "warning: no '$identity' signing identity; installing ad-hoc signed (Keychain will ask again after each update)" >&2
fi
echo "Installing $dest (sudo asks for your password)."
sudo install -d -o root -g wheel -m 755 "$(dirname "$dest")"
sudo install -o root -g wheel -m 755 target/release/cred "$dest"
echo "installed $dest"

# The browser runner (cred's sandboxed browsing), with its pinned playwright-core, root-owned too.
runner=/usr/local/lib/cred/runner
(cd runner && npm ci --ignore-scripts --no-audit --no-fund --silent)
node runner/node_modules/playwright-core/cli.js install chromium-headless-shell >/dev/null
sudo rm -rf "$runner"
sudo install -d -o root -g wheel -m 755 "$runner"
sudo cp -R runner/runner.mjs runner/package.json runner/package-lock.json runner/node_modules "$runner/"
sudo chown -R root:wheel "$runner"
echo "installed $runner"

# The image of the agent VM for boxes, built with Apple's container. Only boxes need it, so a
# missing or stopped container is a note, not a failure.
if ! command -v container >/dev/null 2>&1; then
  echo "note: Apple's container isn't installed, so boxes won't run: https://github.com/apple/container/releases" >&2
elif ! container system status >/dev/null 2>&1; then
  echo "note: container's system isn't running; run 'container system start', then install.sh again to build the agent image" >&2
elif container build -f box/agent.Containerfile -t cred-agent box; then
  echo "built the agent image cred-agent"
else
  echo "warning: building the agent image failed; boxes won't run until 'container build' of box/agent.Containerfile works" >&2
fi

# Keychain items are tied to the build that wrote them, so a new cred can't read the old
# approvals silently: approve the policies again, with one Touch ID for all of them.
if [ -n "$(ls "$HOME/.config/cred/policy/"*.toml 2>/dev/null)" ]; then
  echo "Approve your policies again (Touch ID):"
  "$dest" policy approve || echo "skipped: run 'cred policy approve' to re-enable your sites" >&2
fi
