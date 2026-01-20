use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

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

fn main() -> Result<()> {
    let args = Args::parse();

    let cfg = pcap_ts_core::ExtractConfig {
        dst_port: args.dst_port,
        src_port: args.src_port,
        strip_rtp: args.strip_rtp,
        sync_checks: args.sync_checks,
        dry_run: args.dry_run,
    };

    let report = pcap_ts_core::extract_pcap_to_ts(
        &args.input,
        if args.dry_run { None } else { Some(&args.output) },
        &cfg,
    )?;

    eprintln!("PCAP frames seen:            {}", report.frames_total);
    eprintln!("UDP frames matched filters:  {}", report.udp_matched);
    eprintln!("TS packet size detected:     {}", report.detected_ts_packet_size);
    eprintln!("TS packets written:          {}", report.ts_packets_written);
    if cfg.dry_run {
        eprintln!("Dry run: no output written");
    } else if let Some(out) = report.output.as_ref() {
        eprintln!("Output: {:?}", out);
    }
    eprintln!(
        "Elapsed: {}.{:03}s",
        report.elapsed.as_secs(),
        report.elapsed.subsec_millis()
    );

    Ok(())
}

