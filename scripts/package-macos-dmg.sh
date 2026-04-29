#!/usr/bin/env bash

set -euo pipefail

APP_NAME="PCAPtoTS"
BUNDLE_ID="com.jonnsandon.pcapts.desktop"
MIN_MACOS_VERSION="13.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "${REPO_ROOT}/crates/cli/Cargo.toml" | head -n 1
)"

if [[ -z "${VERSION}" ]]; then
  echo "Failed to determine version from crates/cli/Cargo.toml" >&2
  exit 1
fi

DIST_DIR="${REPO_ROOT}/dist"
STAGE_DIR="${DIST_DIR}/dmg-root"
APP_DIR="${STAGE_DIR}/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
CLI_DIR="${STAGE_DIR}/bin"
DMG_PATH="${DIST_DIR}/${APP_NAME}-${VERSION}-macos.dmg"

DESKTOP_BIN="${REPO_ROOT}/target/release/pcap_ts_desktop"
CLI_BIN="${REPO_ROOT}/target/release/pcap_ts_extract"

echo "Building release binaries..."
cargo build --release --bins --manifest-path "${REPO_ROOT}/Cargo.toml"

echo "Preparing DMG staging directory..."
rm -rf "${STAGE_DIR}"
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}" "${CLI_DIR}"

cp "${DESKTOP_BIN}" "${MACOS_DIR}/${APP_NAME}"
cp "${CLI_BIN}" "${CLI_DIR}/pcap_ts_extract"
chmod +x "${MACOS_DIR}/${APP_NAME}" "${CLI_DIR}/pcap_ts_extract"

cat > "${CONTENTS_DIR}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>${MIN_MACOS_VERSION}</string>
</dict>
</plist>
PLIST

if [[ -f "${REPO_ROOT}/resources/AppIcon.icns" ]]; then
  cp "${REPO_ROOT}/resources/AppIcon.icns" "${RESOURCES_DIR}/AppIcon.icns"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon.icns" "${CONTENTS_DIR}/Info.plist"
fi

ln -sfn /Applications "${STAGE_DIR}/Applications"

cat > "${STAGE_DIR}/README.txt" <<EOF
${APP_NAME}

Desktop app:
- Drag ${APP_NAME}.app into Applications, or launch it directly from the DMG.

CLI:
- Copy bin/pcap_ts_extract somewhere on your PATH, for example /usr/local/bin.
- Example:
    cp bin/pcap_ts_extract /usr/local/bin/
EOF

echo "Creating DMG..."
rm -f "${DMG_PATH}"
hdiutil create \
  -volname "${APP_NAME}" \
  -srcfolder "${STAGE_DIR}" \
  -format UDZO \
  "${DMG_PATH}"

echo "Created ${DMG_PATH}"
