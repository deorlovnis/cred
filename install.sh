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
  # The JVM variant (a JDK and the Kotlin language server), from exactly that build. The builder
  # looks a digest up on Docker Hub, so it gets the cred-agent:<hex> tag cred itself runs images by.
  digest=$(container image inspect cred-agent | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s)[0].configuration.descriptor.digest))')
  container image tag cred-agent "cred-agent:${digest#sha256:}"
  if container build -f box/agent-jvm.Containerfile -t cred-agent-jvm --build-arg "AGENT=cred-agent:${digest#sha256:}" box; then
    echo "built the JVM agent image cred-agent-jvm"
  else
    echo "warning: building the JVM agent image failed; boxes pinned to cred-agent-jvm won't run until it builds" >&2
  fi
  if container build -f box/agent-rust.Containerfile -t cred-agent-rust --build-arg "AGENT=cred-agent:${digest#sha256:}" box; then
    echo "built the Rust agent image cred-agent-rust"
  else
    echo "warning: building the Rust agent image failed; boxes pinned to cred-agent-rust won't run until it builds" >&2
  fi
else
  echo "warning: building the agent image failed; boxes won't run until 'container build' of box/agent.Containerfile works" >&2
fi
# The browser VM's image: cred's runner and Chromium for the box's sites. Built with the repo as
# the context (.dockerignore keeps the rest out). Needed only by boxes with sites that browse.
if command -v container >/dev/null 2>&1 && container system status >/dev/null 2>&1; then
  if container build -f box/browser.Containerfile -t cred-browser .; then
    echo "built the browser image cred-browser"
  else
    echo "warning: building the browser image failed; boxes can't browse until 'container build' of box/browser.Containerfile works" >&2
  fi
fi

# Keychain items are tied to the build that wrote them, so a new cred can't read the old
# approvals silently: approve the policies again, with one Touch ID for all of them.
if [ -n "$(ls "$HOME/.config/cred/policy/"*.toml "$HOME/.config/cred/box/"*.toml 2>/dev/null)" ]; then
  echo "Approve your policies again (Touch ID):"
  "$dest" policy approve || echo "skipped: run 'cred policy approve' to re-enable your sites" >&2
fi
