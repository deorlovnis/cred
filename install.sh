#!/bin/sh
# Build, sign and install cred as /usr/local/bin/cred, owned by root so nothing running as you
# can replace it.
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
