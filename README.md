# pcap_ts_extract

Extract MPEG-TS packets from UDP (optionally RTP) inside PCAP/PCAPNG files. This repo is set up as a teaching tool for practical Rust: clear data flow, small API surface, and documentation that maps directly to the code you can read and test.

## Repository layout

- `crates/core`: Library crate with the extraction engine and evented API.
- `crates/cli`: Command-line frontend using `clap`.
- `crates/desktop_egui`: Desktop GUI frontend using `eframe/egui`.
- `resources`: App icon and related assets.

## Architectural overview

The core design is deliberately linear and observable:

1) Read capture blocks (PCAP or PCAPNG) with `pcap-parser`.
2) Normalize link-layer framing (Ethernet/IP) and parse transport headers with `etherparse`.
3) Filter UDP frames by optional source/destination ports.
4) Optionally strip RTP headers.
5) Detect MPEG-TS packet size (188/192/204) using sync byte heuristics.
6) Re-sync packet boundaries and stream aligned TS packets to output.

The CLI and desktop app are thin wrappers that translate user input into `pcap_ts_core::ExtractConfig` and display `ExtractReport` plus progress events.

## Crate documentation map

### `pcap_ts_core` (library)

Key types and functions (see `crates/core/src/lib.rs` for full rustdoc):

- `ExtractConfig`: Options for filtering, RTP stripping, sync detection, and dry runs.
- `ExtractEvent`: Progress events for UIs or logging.
- `ExtractReport`: Summary of an extraction run.
- `extract_pcap_to_ts`: Simple synchronous API.
- `extract_pcap_to_ts_with_events`: Evented API with cancellation.
- `TsResyncWriter`: Internal buffering and re-sync logic for TS alignment.
- `detect_ts_packet_size`: Heuristic for TS packet size detection.
- `strip_rtp` and `looks_like_rtp`: Lightweight RTP header handling.

### `pcap_ts_extract` (CLI)

`crates/cli/src/main.rs` is intentionally small:

- Parse arguments.
- Build `ExtractConfig`.
- Call `extract_pcap_to_ts`.
- Print a human-readable summary.

### `pcap_ts_desktop` (GUI)

`crates/desktop_egui/src/main.rs` shows an idiomatic evented UI:

- A `DesktopApp` state machine.
- A background worker thread for extraction.
- A channel for log/progress messages.
- A small cancel flag for cooperative shutdown.

## Teaching highlights (Rust concepts in practice)

- Ownership across threads: `Arc<AtomicBool>` and `crossbeam-channel`.
- Error handling with `anyhow` and contextual errors.
- Bounded buffering and streaming I/O with `BufReader`/`BufWriter`.
- Simple state machines in UI code.
- Clean API surface that supports both CLI and GUI.

## Quick start

Build all crates:

```bash
cargo build
```

Run the CLI:

```bash
cargo run -p pcap_ts_extract -- --input capture.pcapng --output output.ts --dst-port 5004
```

Dry run (stats only):

```bash
cargo run -p pcap_ts_extract -- --input capture.pcapng --output output.ts --dry-run
```

Run the desktop app:

```bash
cargo run -p pcap_ts_desktop
```

## Test harness and documentation

Rust makes docs executable. The core API includes a `no_run` example so `cargo test` and `cargo test --doc` exercise it without needing an actual PCAP file.

Suggested commands:

```bash
# Run unit and doc tests for the core library
cargo test -p pcap_ts_core

# Run doc tests only (includes README examples if you add them to rustdoc)
cargo test -p pcap_ts_core --doc

# Build docs and open locally
cargo doc -p pcap_ts_core --open
```

Desktop crate tests:

```bash
# Run desktop unit tests (basic state + icon decode)
cargo test -p pcap_ts_desktop
```

Note: the desktop crate is a GUI binary, so there are no UI snapshot tests by default. The included tests are light sanity checks; for full verification, run the app and exercise the workflow manually.

## Roadmap ideas

- Add optional PCR/PTS timing reports for teaching timebase concepts.
- Add a small sample PCAP and a golden TS file for regression tests.
- Extend RTP handling to parse header fields for richer debug output.
- Add CLI output formats (CSV/JSON) for scripting.
- Add a library-level `Iterator` API for streaming TS packets.

## Contribution notes

This project is meant to be read. If you add features, keep the flow simple and document the "why" as much as the "what".
