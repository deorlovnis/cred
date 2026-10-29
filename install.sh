#!/bin/sh
# Build, sign and install cred to ~/.local/bin.
#
# Signing with a stable identity keeps macOS "Always Allow" Keychain approvals across
# rebuilds; an ad-hoc signed build counts as a new app every time. Without the identity
# the build is installed ad-hoc signed, with a warning. See README "Signing".
set -eu
cd "$(dirname "$0")"
identity="${CRED_SIGN_IDENTITY:-cred code signing}"
dest="${CRED_INSTALL_DIR:-$HOME/.local/bin}"

cargo build --release
if security find-identity -p codesigning | grep -qF "\"$identity\""; then
  codesign --force --sign "$identity" --identifier com.deorlovnis.cred target/release/cred
else
  echo "warning: no '$identity' signing identity; installing ad-hoc signed (Keychain will ask again after each update)" >&2
fi
mkdir -p "$dest"
install -m 755 target/release/cred "$dest/cred"
echo "installed $dest/cred"
