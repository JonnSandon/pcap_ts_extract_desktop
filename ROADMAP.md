# Roadmap

## Intent

`pcap_ts_extract` is moving from a straightforward UDP TS extractor toward a capture-analysis tool with pluggable payload normalization.

The key change is architectural: stop treating every failure as "TS sync not found" and instead expose what sits between UDP and TS.

## Current Phase

Phase 1 is complete enough to be useful:

- shared core crate
- CLI frontend
- desktop frontend
- Rust `1.95.0` compatibility
- baseline support for `pcap` and `pcapng`
- baseline support for multiple link-layer presentations

## Next Phase

Phase 2 should focus on protocol normalization and observability.

### 1. Payload Probe Layer

Add a probe stage in the core crate that classifies UDP payloads as one of:

- direct TS
- RTP carrying TS
- fixed-size shim before TS
- unsupported or unknown

Expected result:

- fewer silent misses
- clearer logs
- easier extension when new field captures arrive

### 2. Encapsulation Registry

Define decoders as small explicit handlers rather than embedding heuristics inline.

Initial candidates:

- RTP
- fixed 16-byte shim
- confirmed RIST-related wrapper if sample captures prove it
- confirmed SRT-related wrapper if sample captures prove it

Expected result:

- bounded complexity
- unit-testable decapsulation rules
- safer growth path

### 3. Operator Diagnostics

Expose more analysis in CLI and GUI:

- detected link type
- matched UDP flow summary
- guessed encapsulation
- first TS sync offset
- packet-size confidence
- count of packets rejected before decapsulation

Expected result:

- faster confirmation on field captures
- less guesswork

### 4. Sample-Driven Regression

Build a small regression corpus:

- direct UDP TS
- RTP over UDP TS
- Linux cooked capture
- loopback/raw IP capture
- one or more shimmed captures

Expected result:

- new decoders can be added without breaking working cases

## Open Technical Questions

- Is the observed 16-byte shim constant per flow or per packet family?
- Is the shim purely transport metadata or does it include sequencing/recovery fields?
- Does TS always begin at a stable offset after the shim?
- Are RIST and SRT both present in the target deployment, or is only one protocol family relevant?
- Should decapsulation be automatic, or selectable with an override flag in CLI/GUI?

Current evidence from field capture `dump_rt_gw_28042026_1340.pcap`:

- yes, the dominant media flow shows a stable `+16` TS offset
- yes, the next sync on many sampled packets appears at `+204`
- the reverse-direction packets do not look like TS payload packets
- this currently favors an SRT/UDT-style framing hypothesis over RTP

## Proposed Short-Term Deliverables

1. Add capture-inspection mode in the core/CLI to print payload prefixes and likely TS offsets.
2. Add an internal `PayloadKind` enum and probe function.
3. Add one confirmed shim decoder once a real sample capture is available.
4. Add GUI output showing detected payload kind and sync offset.

## Definition Of Done For The Next Milestone

The next milestone is complete when:

- a sample shimmed capture has been analyzed
- the encapsulation is identified or clearly bounded
- the extractor can recover TS from that capture
- the behavior is covered by an automated regression test
