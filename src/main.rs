use anyhow::{anyhow, Context, Result};
use clap::Parser;
use etherparse::{PacketHeaders, TransportHeader};
use pcap_parser::data::{get_packetdata, PacketData};
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::*;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "pcap_ts_extract",
    about = "Extract MPEG-TS (188-byte) packets from UDP (optionally RTP) in a PCAP/PCAPNG"
)]
struct Args {
    /// Input .pcap or .pcapng file
    #[arg(short, long)]
    input: PathBuf,

    /// Output .ts file
    #[arg(short, long)]
    output: PathBuf,

    /// Filter UDP destination port (common: 1234, 5004, 10000, etc.)
    #[arg(long)]
    dst_port: Option<u16>,

    /// Filter UDP source port
    #[arg(long)]
    src_port: Option<u16>,

    /// Try to detect and strip RTP header before TS re-sync
    #[arg(long, default_value_t = true)]
    strip_rtp: bool,

    /// How many consecutive sync checks to validate a candidate TS packet size
    #[arg(long, default_value_t = 3)]
    sync_checks: usize,

    /// Stats only; do not write an output file
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

fn looks_like_rtp(payload: &[u8]) -> bool {
    // RTP: V=2 => top two bits of first byte are 10b (0x80..0xBF)
    payload.len() >= 12 && (payload[0] & 0xC0) == 0x80
}

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

struct TsResyncWriter<W: Write> {
    out: W,
    buf: Vec<u8>,
    sync_checks: usize,
    packet_size: usize,
    written_packets: u64,
}

impl<W: Write> TsResyncWriter<W> {
    fn new(out: W, packet_size: usize, sync_checks: usize) -> Self {
        Self {
            out,
            buf: Vec::with_capacity(packet_size * 20),
            sync_checks: sync_checks.max(1),
            packet_size: packet_size.max(1),
            written_packets: 0,
        }
    }

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

    fn flush_out(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

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

/// Extract packet data and normalize link-layer framing across pcap/pcapng linktypes.
fn extract_packet_data<'a>(
    block: &'a PcapBlockOwned<'a>,
    legacy_linktype: Option<Linktype>,
    if_linktypes: &[Linktype],
) -> Option<PacketData<'a>> {
    match block {
        PcapBlockOwned::Legacy(b) => {
            let linktype = legacy_linktype.unwrap_or(Linktype::ETHERNET);
            get_packetdata(b.data, linktype, b.caplen as usize)
        }
        PcapBlockOwned::LegacyHeader(_) => None,
        PcapBlockOwned::NG(b) => match b {
            Block::EnhancedPacket(epb) => {
                let linktype = if_linktypes
                    .get(epb.if_id as usize)
                    .copied()
                    .unwrap_or(Linktype::ETHERNET);
                let data = epb.packet_data();
                get_packetdata(data, linktype, data.len())
            }
            Block::SimplePacket(spb) => {
                let linktype = if_linktypes.get(0).copied().unwrap_or(Linktype::ETHERNET);
                let data = spb.packet_data();
                get_packetdata(data, linktype, data.len())
            }
            _ => None,
        },
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();

    let f = File::open(&args.input).with_context(|| format!("open input {:?}", args.input))?;
    let mut reader = BufReader::new(f);

    let out: Box<dyn Write> = if args.dry_run {
        Box::new(std::io::sink())
    } else {
        let out_f =
            File::create(&args.output).with_context(|| format!("create output {:?}", args.output))?;
        Box::new(BufWriter::new(out_f))
    };

    // create_reader handles PCAP or PCAPNG
    let mut pcap = create_reader(65536, &mut reader)
        .map_err(|e| anyhow!("pcap create_reader: {e:?}"))?;

    let mut frames_total: u64 = 0;
    let mut udp_matched: u64 = 0;
    let mut legacy_linktype: Option<Linktype> = None;
    let mut if_linktypes: Vec<Linktype> = Vec::new();
    let mut written_packets: u64 = 0;
    let mut detected_packet_size: Option<usize> = None;
    let mut detect_buf: Vec<u8> = Vec::new();
    let mut out_writer: Option<Box<dyn Write>> = Some(out);
    let mut tsw: Option<TsResyncWriter<Box<dyn Write>>> = None;
    {
        let max_detect_buf = 204usize * 400;

        loop {
            match pcap.next() {
                Ok((offset, block)) => {
                    frames_total += 1;

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
                        let headers = match packet_data {
                            PacketData::L2(data) => PacketHeaders::from_ethernet_slice(data).ok(),
                            PacketData::L3(_, data) => PacketHeaders::from_ip_slice(data).ok(),
                            PacketData::L4(_, _) | PacketData::Unsupported(_) => None,
                        };

                        if let Some(headers) = headers {
                            if let Some(TransportHeader::Udp(udp_hdr)) = headers.transport {
                                if let Some(dp) = args.dst_port {
                                    if udp_hdr.destination_port != dp {
                                        pcap.consume(offset);
                                        continue;
                                    }
                                }
                                if let Some(sp) = args.src_port {
                                    if udp_hdr.source_port != sp {
                                        pcap.consume(offset);
                                        continue;
                                    }
                                }

                                udp_matched += 1;

                                // PayloadSlice -> &[u8]
                                let mut payload: &[u8] = headers.payload.slice();

                                if args.strip_rtp {
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
                                            detect_ts_packet_size(&detect_buf, args.sync_checks);
                                        if let Some(size) = detected_packet_size {
                                            let writer = out_writer
                                                .take()
                                                .ok_or_else(|| anyhow!("missing output writer"))?;
                                            let mut new_tsw = TsResyncWriter::new(
                                                writer,
                                                size,
                                                args.sync_checks,
                                            );
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
            let writer = out_writer
                .take()
                .ok_or_else(|| anyhow!("missing output writer"))?;
            let mut new_tsw = TsResyncWriter::new(writer, size, args.sync_checks);
            if !detect_buf.is_empty() {
                new_tsw.push_payload(&detect_buf)?;
                detect_buf.clear();
            }
            tsw = Some(new_tsw);
        }

        if let Some(tsw) = tsw.as_mut() {
            written_packets = tsw.written_packets;
            tsw.flush_out()?;
        }
    }

    eprintln!("PCAP frames seen:            {}", frames_total);
    eprintln!("UDP frames matched filters:  {}", udp_matched);
    if let Some(size) = detected_packet_size {
        eprintln!("TS packet size detected:     {}", size);
    }
    eprintln!("TS packets written:          {}", written_packets);
    if args.dry_run {
        eprintln!("Dry run: no output written");
    } else {
        eprintln!("Output: {:?}", args.output);
    }
    let elapsed = start.elapsed();
    eprintln!("Elapsed: {}.{:03}s", elapsed.as_secs(), elapsed.subsec_millis());

    Ok(())
}
