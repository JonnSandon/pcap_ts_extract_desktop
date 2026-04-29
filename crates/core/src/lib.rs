//! Core library for extracting MPEG-TS packets from UDP (optionally RTP) in PCAP/PCAPNG files.
//!
//! Design goals:
//! - Treat PCAP and PCAPNG uniformly via `pcap-parser`.
//! - Filter by UDP ports when requested.
//! - Optionally strip RTP headers and re-sync to MPEG-TS packet boundaries.
//! - Stream output to avoid unbounded memory growth.
//!
//! This crate exposes a small API surface so it can be used by both the CLI and GUI frontends.

use anyhow::{Context, Result, anyhow};
use etherparse::{PacketHeaders, TransportHeader, UdpSlice};
use pcap_parser::data::{PacketData, get_packetdata};
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::*;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Configuration for a PCAP extraction run.
#[derive(Debug, Clone)]
pub struct ExtractConfig {
    /// Optional UDP destination port filter.
    pub dst_port: Option<u16>,
    /// Optional UDP source port filter.
    pub src_port: Option<u16>,
    /// If true, attempt to strip RTP headers before TS re-sync.
    pub strip_rtp: bool,
    /// Number of consecutive sync checks for TS packet detection.
    pub sync_checks: usize,
    /// If true, do not write output (stats only).
    pub dry_run: bool,
}
/// Progress events emitted by `extract_pcap_to_ts_with_events`.
#[derive(Debug, Clone)]
pub enum ExtractEvent {
    /// Count of frames seen and UDP frames matched so far.
    Frame { frames_total: u64, udp_matched: u64 },
    /// Detected TS packet size (188/192/204).
    DetectedPacketSize { size: usize },
    /// Number of TS packets written so far.
    WrittenPackets { ts_packets_written: u64 },
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            dst_port: None,
            src_port: None,
            strip_rtp: true,
            sync_checks: 3,
            dry_run: false,
        }
    }
}

/// Summary report returned after extraction completes.
#[derive(Debug, Clone)]
pub struct ExtractReport {
    /// Total frames parsed from the capture.
    pub frames_total: u64,
    /// UDP frames that matched filters and were processed.
    pub udp_matched: u64,
    /// Detected TS packet size in bytes.
    pub detected_ts_packet_size: usize,
    /// Number of TS packets written to output.
    pub ts_packets_written: u64,
    /// Output path when not in dry-run mode.
    pub output: Option<PathBuf>,
    /// Total elapsed time.
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Copy)]
struct UdpDatagram<'a> {
    source_port: u16,
    destination_port: u16,
    payload: &'a [u8],
}

/// Heuristically determine if a payload appears to be RTP.
fn looks_like_rtp(payload: &[u8]) -> bool {
    // RTP: V=2 => top two bits of first byte are 10b (0x80..0xBF)
    payload.len() >= 12 && (payload[0] & 0xC0) == 0x80
}

/// Strip RTP header (including CSRC and extension), if present.
fn strip_rtp(payload: &[u8]) -> &[u8] {
    if !looks_like_rtp(payload) {
        return payload;
    }
    // RTP header length: 12 + 4*CC (+ extension if X set)
    let cc = (payload[0] & 0x0F) as usize;
    let x = (payload[0] & 0x10) != 0;
    let mut off = 12 + cc * 4;
    if payload.len() < off {
        return payload;
    }
    if x {
        // Extension header: 16-bit profile, 16-bit length (in 32-bit words), then extension data.
        if payload.len() < off + 4 {
            return payload;
        }
        let ext_len_words = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
        off += 4 + ext_len_words * 4;
        if payload.len() < off {
            return payload;
        }
    }
    &payload[off..]
}

/// Stateful writer that re-syncs TS packets and writes only aligned packets.
struct TsResyncWriter<W: Write> {
    out: W,
    buf: Vec<u8>,
    sync_checks: usize,
    packet_size: usize,
    written_packets: u64,
}

impl<W: Write> TsResyncWriter<W> {
    /// Create a new TS re-syncing writer.
    fn new(out: W, packet_size: usize, sync_checks: usize) -> Self {
        Self {
            out,
            buf: Vec::with_capacity(packet_size * 20),
            sync_checks: sync_checks.max(1),
            packet_size: packet_size.max(1),
            written_packets: 0,
        }
    }

    /// Check whether the buffer has a valid sync pattern at a given offset.
    fn validate_sync_at(&self, start: usize) -> bool {
        if self.buf.get(start) != Some(&0x47) {
            return false;
        }
        for k in 1..=self.sync_checks {
            let idx = start + self.packet_size * k;
            if idx >= self.buf.len() {
                break; // not enough data yet; defer decision
            }
            if self.buf[idx] != 0x47 {
                return false;
            }
        }
        true
    }

    /// Push a new payload chunk and write any aligned TS packets.
    fn push_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(payload);

        loop {
            if self.buf.len() < self.packet_size {
                return Ok(());
            }

            // If aligned and still looks like TS, write packets
            if self.buf[0] == 0x47 && self.validate_sync_at(0) {
                while self.buf.len() >= self.packet_size && self.buf[0] == 0x47 {
                    self.out.write_all(&self.buf[..self.packet_size])?;
                    self.buf.drain(..self.packet_size);
                    self.written_packets += 1;

                    if self.buf.len() < self.packet_size {
                        break;
                    }
                    if self.buf[0] != 0x47 {
                        break;
                    }
                }
                continue;
            }

            // Search for next plausible sync position
            let mut found = None;
            for i in 1..self.buf.len() {
                if self.buf[i] == 0x47 && self.validate_sync_at(i) {
                    found = Some(i);
                    break;
                }
            }

            match found {
                Some(i) => {
                    self.buf.drain(..i);
                    continue;
                }
                None => {
                    // avoid unbounded growth: keep last ~10 packets worth
                    let keep = self.packet_size * 10;
                    if self.buf.len() > keep {
                        let drop = self.buf.len() - keep;
                        self.buf.drain(..drop);
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Flush underlying writer.
    fn flush_out(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

/// Detect MPEG-TS packet size from a rolling buffer of bytes.
fn detect_ts_packet_size(buf: &[u8], sync_checks: usize) -> Option<usize> {
    let candidates = [188usize, 192, 204];
    let mut best: Option<(usize, usize)> = None;
    let checks = sync_checks.max(1);

    for &size in &candidates {
        if buf.len() < size * (checks + 1) {
            continue;
        }
        let mut best_score = 0usize;
        for start in 0..size {
            if start >= buf.len() {
                break;
            }
            if buf[start] != 0x47 {
                continue;
            }
            let mut score = 0usize;
            for k in 1..=checks {
                let idx = start + size * k;
                if idx >= buf.len() {
                    break;
                }
                if buf[idx] == 0x47 {
                    score += 1;
                } else {
                    score = 0;
                    break;
                }
            }
            if score > best_score {
                best_score = score;
                if best_score >= checks {
                    break;
                }
            }
        }
        if best_score >= checks {
            match best {
                Some((prev_score, _)) if prev_score >= best_score => {}
                _ => best = Some((best_score, size)),
            }
        }
    }

    best.map(|(_, size)| size)
}

fn get_packetdata_loop(i: &[u8], caplen: usize) -> Option<PacketData<'_>> {
    if i.len() < caplen || caplen < 4 {
        return None;
    }

    let vers = u32::from_be_bytes(i[..4].try_into().ok()?);
    let ethertype = match vers {
        2 => pcap_parser::data::ETHERTYPE_IPV4,
        24 | 28 | 30 => pcap_parser::data::ETHERTYPE_IPV6,
        _ => 0,
    };

    Some(PacketData::L3(ethertype, &i[4..caplen]))
}

fn get_packetdata_for_linktype<'a>(
    data: &'a [u8],
    linktype: Linktype,
    caplen: usize,
) -> Option<PacketData<'a>> {
    match linktype {
        Linktype::LOOP => get_packetdata_loop(data, caplen),
        _ => get_packetdata(data, linktype, caplen),
    }
}

fn udp_datagram_from_headers(headers: PacketHeaders<'_>) -> Option<UdpDatagram<'_>> {
    match headers.transport {
        Some(TransportHeader::Udp(udp_hdr)) => Some(UdpDatagram {
            source_port: udp_hdr.source_port,
            destination_port: udp_hdr.destination_port,
            payload: headers.payload.slice(),
        }),
        _ => None,
    }
}

fn udp_datagram_from_packet_data(packet_data: PacketData<'_>) -> Option<UdpDatagram<'_>> {
    match packet_data {
        PacketData::L2(data) => PacketHeaders::from_ethernet_slice(data)
            .ok()
            .and_then(udp_datagram_from_headers),
        PacketData::L3(_, data) => PacketHeaders::from_ip_slice(data)
            .ok()
            .and_then(udp_datagram_from_headers),
        PacketData::L4(17, data) => UdpSlice::from_slice(data).ok().map(|udp| UdpDatagram {
            source_port: udp.source_port(),
            destination_port: udp.destination_port(),
            payload: udp.payload(),
        }),
        PacketData::L4(_, _) | PacketData::Unsupported(_) => None,
    }
}

/// Extract packet data and normalize link-layer framing across pcap/pcapng linktypes.
fn extract_packet_data<'a>(
    block: &'a PcapBlockOwned<'a>,
    legacy_linktype: Option<Linktype>,
    if_linktypes: &[Linktype],
) -> Option<PacketData<'a>> {
    match block {
        PcapBlockOwned::Legacy(b) => {
            let linktype = legacy_linktype.unwrap_or(Linktype::ETHERNET);
            get_packetdata_for_linktype(b.data, linktype, b.caplen as usize)
        }
        PcapBlockOwned::LegacyHeader(_) => None,
        PcapBlockOwned::NG(b) => match b {
            Block::EnhancedPacket(epb) => {
                let linktype = if_linktypes
                    .get(epb.if_id as usize)
                    .copied()
                    .unwrap_or(Linktype::ETHERNET);
                let data = epb.packet_data();
                get_packetdata_for_linktype(data, linktype, data.len())
            }
            Block::SimplePacket(spb) => {
                let linktype = if_linktypes.get(0).copied().unwrap_or(Linktype::ETHERNET);
                let data = spb.packet_data();
                get_packetdata_for_linktype(data, linktype, data.len())
            }
            _ => None,
        },
    }
}

/// Core API: extract MPEG-TS packets from UDP (optionally RTP) inside a PCAP/PCAPNG.
///
/// Returns a report; writes output unless `dry_run=true`.
///
/// # Example
/// ```rust,no_run
/// use pcap_ts_core::{ExtractConfig, extract_pcap_to_ts};
/// use std::path::Path;
///
/// let cfg = ExtractConfig {
///     dst_port: Some(5004),
///     src_port: None,
///     strip_rtp: true,
///     sync_checks: 3,
///     dry_run: true,
/// };
///
/// let report = extract_pcap_to_ts(
///     Path::new("capture.pcapng"),
///     None,
///     &cfg,
/// )?;
/// println!("TS packets: {}", report.ts_packets_written);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn extract_pcap_to_ts(
    input: &Path,
    output: Option<&Path>,
    cfg: &ExtractConfig,
) -> Result<ExtractReport> {
    let cancel = AtomicBool::new(false);
    extract_pcap_to_ts_with_events(input, output, cfg, &cancel, |_| {})
}

/// Extraction API with progress events and cooperative cancellation.
///
/// The `on_event` callback is invoked periodically with progress metrics, and
/// `cancel` can be set to true to abort the run.
pub fn extract_pcap_to_ts_with_events<F: FnMut(ExtractEvent)>(
    input: &Path,
    output: Option<&Path>,
    cfg: &ExtractConfig,
    cancel: &AtomicBool,
    mut on_event: F,
) -> Result<ExtractReport> {
    let start = Instant::now();

    let f = File::open(input).with_context(|| format!("open input {:?}", input))?;
    let mut reader = BufReader::new(f);

    let out: Box<dyn Write> = if cfg.dry_run {
        Box::new(std::io::sink())
    } else {
        let out_path =
            output.ok_or_else(|| anyhow!("output path is required unless dry_run=true"))?;
        let out_f =
            File::create(out_path).with_context(|| format!("create output {:?}", out_path))?;
        Box::new(BufWriter::new(out_f))
    };

    // create_reader handles PCAP or PCAPNG
    let mut pcap =
        create_reader(65536, &mut reader).map_err(|e| anyhow!("pcap create_reader: {e:?}"))?;

    let mut frames_total: u64 = 0;
    let mut udp_matched: u64 = 0;
    let mut legacy_linktype: Option<Linktype> = None;
    let mut if_linktypes: Vec<Linktype> = Vec::new();
    let mut written_packets: u64 = 0;
    let mut detected_packet_size: Option<usize> = None;
    let mut detect_buf: Vec<u8> = Vec::new();
    let mut out_writer: Option<Box<dyn Write>> = Some(out);
    let mut tsw: Option<TsResyncWriter<Box<dyn Write>>> = None;

    let max_detect_buf = 204usize * 400;

    // Emit progress every N frames (tweak as you like)
    let progress_every: u64 = 10_000;

    loop {
        match pcap.next() {
            Ok((offset, block)) => {
                frames_total += 1;

                if frames_total % progress_every == 0 {
                    on_event(ExtractEvent::Frame {
                        frames_total,
                        udp_matched,
                    });
                    if let Some(tsw) = tsw.as_ref() {
                        on_event(ExtractEvent::WrittenPackets {
                            ts_packets_written: tsw.written_packets,
                        });
                    }
                }
                if cancel.load(Ordering::Relaxed) {
                    return Err(anyhow!("Cancelled"));
                }

                match &block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_linktype = Some(h.network);
                        pcap.consume(offset);
                        continue;
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        if_linktypes.push(idb.linktype);
                        pcap.consume(offset);
                        continue;
                    }
                    _ => {}
                }

                if let Some(packet_data) =
                    extract_packet_data(&block, legacy_linktype, &if_linktypes)
                {
                    if let Some(udp) = udp_datagram_from_packet_data(packet_data) {
                        if let Some(dp) = cfg.dst_port {
                            if udp.destination_port != dp {
                                pcap.consume(offset);
                                continue;
                            }
                        }
                        if let Some(sp) = cfg.src_port {
                            if udp.source_port != sp {
                                pcap.consume(offset);
                                continue;
                            }
                        }

                        udp_matched += 1;

                        let mut payload = udp.payload;
                        if cfg.strip_rtp {
                            payload = strip_rtp(payload);
                        }

                        if let Some(tsw) = tsw.as_mut() {
                            tsw.push_payload(payload)?;
                        } else {
                            detect_buf.extend_from_slice(payload);
                            if detect_buf.len() > max_detect_buf {
                                let drop = detect_buf.len() - max_detect_buf;
                                detect_buf.drain(..drop);
                            }
                            if detected_packet_size.is_none() {
                                detected_packet_size =
                                    detect_ts_packet_size(&detect_buf, cfg.sync_checks);
                                if let Some(size) = detected_packet_size {
                                    on_event(ExtractEvent::DetectedPacketSize { size });

                                    let writer = out_writer
                                        .take()
                                        .ok_or_else(|| anyhow!("missing output writer"))?;
                                    let mut new_tsw =
                                        TsResyncWriter::new(writer, size, cfg.sync_checks);
                                    if !detect_buf.is_empty() {
                                        new_tsw.push_payload(&detect_buf)?;
                                        detect_buf.clear();
                                    }
                                    tsw = Some(new_tsw);
                                }
                            }
                        }
                    }
                }

                pcap.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if pcap.reader_exhausted() {
                    break;
                }
                pcap.refill()
                    .map_err(|e| anyhow!("pcap refill error: {e:?}"))?;
                continue;
            }
            Err(e) => return Err(anyhow!("pcap parse error: {e:?}")),
        }
    }

    if tsw.is_none() {
        let size = detected_packet_size.unwrap_or(188);
        detected_packet_size = Some(size);

        on_event(ExtractEvent::DetectedPacketSize { size });

        let writer = out_writer
            .take()
            .ok_or_else(|| anyhow!("missing output writer"))?;
        let mut new_tsw = TsResyncWriter::new(writer, size, cfg.sync_checks);
        if !detect_buf.is_empty() {
            new_tsw.push_payload(&detect_buf)?;
            detect_buf.clear();
        }
        tsw = Some(new_tsw);
    }

    if let Some(tsw) = tsw.as_mut() {
        written_packets = tsw.written_packets;
        on_event(ExtractEvent::WrittenPackets {
            ts_packets_written: written_packets,
        });
        tsw.flush_out()?;
    }

    let elapsed = start.elapsed();
    on_event(ExtractEvent::Frame {
        frames_total,
        udp_matched,
    });

    Ok(ExtractReport {
        frames_total,
        udp_matched,
        detected_ts_packet_size: detected_packet_size.unwrap_or(188),
        ts_packets_written: written_packets,
        output: if cfg.dry_run {
            None
        } else {
            output.map(|p| p.to_path_buf())
        },
        elapsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_linktype_decodes_ipv4_payload() {
        let bytes = [0, 0, 0, 2, 0x45, 0x00, 0x00, 0x14];
        let packet = get_packetdata_loop(&bytes, bytes.len()).expect("loopback packet");

        match packet {
            PacketData::L3(ethertype, payload) => {
                assert_eq!(ethertype, pcap_parser::data::ETHERTYPE_IPV4);
                assert_eq!(payload, &[0x45, 0x00, 0x00, 0x14]);
            }
            other => panic!("unexpected packet data: {other:?}"),
        }
    }

    #[test]
    fn wireshark_upper_pdu_udp_is_accepted() {
        let udp = [
            0x13, 0x8c, 0x13, 0x8d, 0x00, 0x0c, 0x00, 0x00, 0x47, 0x40, 0x00, 0x10,
        ];
        let datagram =
            udp_datagram_from_packet_data(PacketData::L4(17, &udp)).expect("udp datagram");

        assert_eq!(datagram.source_port, 5004);
        assert_eq!(datagram.destination_port, 5005);
        assert_eq!(datagram.payload, &[0x47, 0x40, 0x00, 0x10]);
    }
}
