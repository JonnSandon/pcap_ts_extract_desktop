# pcap_ts_extract

Extract MPEG-TS packets from UDP-oriented captures in `pcap` and `pcapng`, with CLI and desktop frontends backed by a shared Rust core.

The project has moved beyond a minimal extractor. The next phase is to treat capture parsing as a protocol-normalization problem rather than a single Ethernet-to-UDP happy path.

## Status

Current capabilities:

- Parse legacy `pcap` and `pcapng`
- Handle multiple link-layer presentations through `pcap-parser`
- Extract UDP payloads from Ethernet, raw IP, Linux cooked captures, loopback-style captures, and Wireshark upper-PDU exports
- Optionally strip RTP before MPEG-TS re-sync
- Detect TS packet sizes `188`, `192`, and `204`
- Run as either CLI or desktop GUI

Known limitation:

- The extractor still assumes the useful TS payload becomes visible once the packet is reduced to UDP payload. That will not hold for every contribution/distribution protocol. Some captures contain an additional shim or tunnel header between UDP and TS.

## Repository Layout

- `crates/core`: shared extraction engine and progress/event API
- `crates/cli`: command-line frontend
- `crates/desktop_egui`: desktop GUI frontend
- `resources`: icons and image assets
- `ROADMAP.md`: product and architecture direction

## Architecture

Today the core pipeline is:

1. Read capture blocks with `pcap-parser`
2. Normalize link-layer framing into packet data
3. Recover UDP datagrams
4. Optionally strip RTP
5. Detect TS packet size using sync heuristics
6. Re-sync and stream aligned TS packets to output

This works for direct UDP/RTP carriage. The next architectural step is to split stage 4 into a more explicit payload-normalization layer:

1. UDP payload
2. Encapsulation probe
3. Optional decapsulation
4. TS detection and extraction

That change is important if the project is going to support captures containing:

- RTP with extensions
- RIST-adjacent shims or GRE-based carriage
- SRT-derived payload framing
- vendor-specific 16-byte or 20-byte transport shims
- nested tunnel formats discovered from field captures

## Crates

### `pcap_ts_core`

Main types in [crates/core/src/lib.rs](/c:/Others/rust/pcap_ts_extract/crates/core/src/lib.rs:1):

- `ExtractConfig`: filtering and extraction options
- `ExtractEvent`: progress notifications for UI/logging
- `ExtractReport`: extraction summary
- `extract_pcap_to_ts`: synchronous API
- `extract_pcap_to_ts_with_events`: evented API with cancellation

The core crate should remain the protocol-analysis and extraction engine. Frontends should stay thin.

### `pcap_ts_extract`

The CLI in [crates/cli/src/main.rs](/c:/Others/rust/pcap_ts_extract/crates/cli/src/main.rs:1) is intentionally narrow:

- parse arguments
- build `ExtractConfig`
- invoke the core library
- print a concise report

### `pcap_ts_desktop`

The desktop app in [crates/desktop_egui/src/main.rs](/c:/Others/rust/pcap_ts_extract/crates/desktop_egui/src/main.rs:1) provides:

- file selection
- runtime progress
- cancellation
- a lightweight operator-facing UI for inspecting extraction runs

## Build And Run

Build everything:

```powershell
cargo build
```

Run the CLI:

```powershell
cargo run -p pcap_ts_extract -- --input capture.pcapng --output output.ts --dst-port 5004
```

Run a dry run:

```powershell
cargo run -p pcap_ts_extract -- --input capture.pcapng --output output.ts --dry-run
```

Run the desktop app:

```powershell
cargo run -p pcap_ts_desktop
```

## macOS Release And DMG Packaging

If you want a distributable macOS image that includes both frontends, the cleanest layout is:

- `PCAPtoTS.app`: desktop GUI bundle for Finder / Launchpad usage
- `bin/pcap_ts_extract`: CLI binary for terminal users

One-command packaging:

```bash
./scripts/package-macos-dmg.sh
```

Or, if you prefer `make`:

```bash
make package-macos-dmg
```

That script:

- builds both release binaries
- creates a macOS `.app` bundle for the desktop frontend
- adds the CLI binary under `bin/`
- adds an `Applications` shortcut and `README.txt`
- writes the finished DMG under `dist/`

Expected output:

- `dist/PCAPtoTS-1.1.0-macos.dmg`

Manual flow, if you want to inspect or customize it:

Build both release binaries:

```bash
cargo build --release --bins
```

That produces:

- `target/release/pcap_ts_desktop`
- `target/release/pcap_ts_extract`

Create a staging folder for the DMG contents:

```bash
mkdir -p dist/dmg-root/PCAPtoTS.app/Contents/MacOS
mkdir -p dist/dmg-root/PCAPtoTS.app/Contents/Resources
mkdir -p dist/dmg-root/bin
cp target/release/pcap_ts_desktop dist/dmg-root/PCAPtoTS.app/Contents/MacOS/PCAPtoTS
cp target/release/pcap_ts_extract dist/dmg-root/bin/pcap_ts_extract
chmod +x dist/dmg-root/PCAPtoTS.app/Contents/MacOS/PCAPtoTS
chmod +x dist/dmg-root/bin/pcap_ts_extract
```

Create the app bundle metadata:

```bash
cat > dist/dmg-root/PCAPtoTS.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>PCAPtoTS</string>
  <key>CFBundleIdentifier</key>
  <string>com.jonnsandon.pcapts.desktop</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>PCAPtoTS</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.1.0</string>
  <key>CFBundleVersion</key>
  <string>1.1.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
</dict>
</plist>
PLIST
```

At this point you can test the GUI bundle directly:

```bash
open dist/dmg-root/PCAPtoTS.app
```

Create the compressed DMG:

```bash
hdiutil create \
  -volname "PCAPtoTS" \
  -srcfolder dist/dmg-root \
  -format UDZO \
  dist/PCAPtoTS-1.1.0-macos.dmg
```

The resulting image will contain:

- `PCAPtoTS.app` for desktop users
- `bin/pcap_ts_extract` for CLI users

Notes:

- The desktop app already embeds a PNG for the runtime window icon, but Finder app icons require an `.icns` file. If you want a custom Finder icon, add `AppIcon.icns` under `Contents/Resources` and set `CFBundleIconFile` in `Info.plist`.
- For personal/internal distribution, the unsigned DMG above is enough. For public distribution, you should also `codesign`, notarize, and staple both the `.app` and the final DMG.

## Verification

Recommended checks:

```powershell
cargo test
cargo test -p pcap_ts_core --doc
```

Rust toolchain:

- pinned in `rust-toolchain.toml`
- currently validated on Rust `1.95.0`

## Investigating Unknown Shims

Some real-world captures do not expose TS immediately after UDP or RTP. A recurring field symptom is a fixed-size shim, often around `16` bytes, before TS sync begins.

Working hypothesis:

- A fixed 16-byte header after UDP could be a transport shim, tunnel metadata, or contribution-protocol wrapper
- RIST is a plausible candidate in some workflows
- SRT is also plausible in environments where the payload is carried over UDP but the apparent application payload is not direct TS

Current field finding:

- sample capture `dump_rt_gw_28042026_1340.pcap` was inspected outside the repo
- capture link type is `LINKTYPE_LINUX_SLL2`
- dominant media flow is `40821 -> 5020`
- MPEG-TS sync byte `0x47` appears at payload offset `+16` consistently on the dominant flow
- the next sync byte also appears at `+204`, which matches `16-byte shim + 188-byte TS`
- reverse traffic on `5020 -> 40821` does not show the same TS structure and looks like control/feedback traffic

This is strong evidence for a 16-byte transport header ahead of TS. Based on packet shape alone, this looks more SRT/UDT-like than RTP, and more likely SRT-like than RIST. That is still an inference until we add a decoder and validate it across more than one capture.

This should be treated as a capture-analysis problem, not guessed in code. The correct workflow is:

1. Identify the link type used by the capture
2. Identify the UDP 5-tuple carrying the media flow
3. Inspect the first bytes after UDP
4. Check whether `0x47` appears at a stable offset such as `+12`, `+16`, or `+20`
5. Determine whether the offset is constant across packets
6. Promote that pattern into a decoder only after it is confirmed on sample data

## Documentation Direction

The project should now document:

- supported capture/link types
- supported payload normalizations
- confirmed encapsulations
- unconfirmed hypotheses from field captures
- regression samples used to validate decapsulation logic

That work starts here and continues in [ROADMAP.md](/c:/Others/rust/pcap_ts_extract/ROADMAP.md:1).
