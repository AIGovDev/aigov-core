#!/usr/bin/env bash
# Run the two-volume policy rollback test on two disk images mounted as separate filesystems.
#
# Creates two uniquely named disk images, attaches them at mount points inside a fresh work directory, runs the ignored
# test, and then detaches and removes only what this script created. Needs macOS hdiutil and a PostgreSQL admin URL
# (AIGOV_TEST_PG_ADMIN_URL). Nothing is installed and nothing outside the work directory is changed.
set -euo pipefail

: "${AIGOV_TEST_PG_ADMIN_URL:?set AIGOV_TEST_PG_ADMIN_URL to a PostgreSQL admin URL for the databases this test creates}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ID="$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/aigov-two-volume-${ID}.XXXX")"
IMG_A="${WORK}/vol-a-${ID}.dmg"
IMG_B="${WORK}/vol-b-${ID}.dmg"
MNT_A="${WORK}/mnt-a"
MNT_B="${WORK}/mnt-b"
ATTACHED=()

cleanup() {
  for mnt in "${ATTACHED[@]:-}"; do
    [ -n "$mnt" ] && hdiutil detach -quiet "$mnt" >/dev/null 2>&1 || hdiutil detach -force -quiet "$mnt" >/dev/null 2>&1 || true
  done
  rm -rf "$WORK"
  echo "cleaned up: ${ID}"
}
trap cleanup EXIT

mkdir -p "$MNT_A" "$MNT_B"
hdiutil create -quiet -size 64m -fs APFS -volname "aigov-a-${ID}" -type UDIF "$IMG_A"
hdiutil create -quiet -size 64m -fs APFS -volname "aigov-b-${ID}" -type UDIF "$IMG_B"
hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$MNT_A" "$IMG_A" >/dev/null
ATTACHED+=("$MNT_A")
hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$MNT_B" "$IMG_B" >/dev/null
ATTACHED+=("$MNT_B")

echo "volume A: ${MNT_A} (device $(stat -f %d "$MNT_A"))"
echo "volume B: ${MNT_B} (device $(stat -f %d "$MNT_B"))"

cd "${REPO}/rust"
AIGOV_TEST_VOLUME_A="${MNT_A}" AIGOV_TEST_VOLUME_B="${MNT_B}" LC_ALL=C \
  cargo test --locked --test two_volume_rollback_pg -- --ignored --nocapture
echo "two-volume-rollback: OK"
