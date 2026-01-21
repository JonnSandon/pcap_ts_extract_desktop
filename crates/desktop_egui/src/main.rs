#![windows_subsystem = "windows"]

//! Desktop GUI frontend built with eframe/egui.

use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::egui;
use std::path::PathBuf;
use std::thread;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};


/// Worker thread messages sent back to the UI.
enum Msg {
    Log(String),
    Progress(pcap_ts_core::ExtractEvent),
    Done(anyhow::Result<pcap_ts_core::ExtractReport>),
}


/// Application state for the desktop UI.
struct DesktopApp {
    // inputs
    input: Option<PathBuf>,
    output: Option<PathBuf>,

    // options
    dst_port: Option<u16>,
    src_port: Option<u16>,
    strip_rtp: bool,
    sync_checks: usize,
    dry_run: bool,
    cancel: Arc<AtomicBool>,


    // state
    running: bool,
    rx: Option<Receiver<Msg>>,
    log: Vec<String>,
    last_report: Option<pcap_ts_core::ExtractReport>,
    last_error: Option<String>,
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self {
            input: None,
            output: None,
            dst_port: None,
            src_port: None,
            strip_rtp: true,
            sync_checks: 3,
            dry_run: false,
            running: false,
            rx: None,
            log: vec![],
            last_report: None,
            last_error: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl DesktopApp {
    /// Validate inputs and launch the worker thread.
    fn start(&mut self) {
        self.last_error = None;
        self.last_report = None;
        self.log.clear();
        self.cancel.store(false, Ordering::Relaxed);


        let input = match self.input.clone() {
            Some(p) => p,
            None => {
                self.last_error = Some("Pick an input PCAP/PCAPNG first.".into());
                return;
            }
        };

        let output = if self.dry_run {
            None
        } else {
            match self.output.clone() {
                Some(p) => Some(p),
                None => {
                    self.last_error = Some("Pick an output .ts path (or enable Dry run).".into());
                    return;
                }
            }
        };

        let cfg = pcap_ts_core::ExtractConfig {
            dst_port: self.dst_port,
            src_port: self.src_port,
            strip_rtp: self.strip_rtp,
            sync_checks: self.sync_checks,
            dry_run: self.dry_run,
        };

        let (tx, rx) = unbounded::<Msg>();
        self.rx = Some(rx);
        self.running = true;

        tx.send(Msg::Log(format!("Input:  {}", input.display()))).ok();
        if let Some(out) = &output {
            tx.send(Msg::Log(format!("Output: {}", out.display()))).ok();
        } else {
            tx.send(Msg::Log("Dry run: output disabled".into())).ok();
        }
        tx.send(Msg::Log(format!(
            "Options: dst_port={:?} src_port={:?} strip_rtp={} sync_checks={}",
            cfg.dst_port, cfg.src_port, cfg.strip_rtp, cfg.sync_checks
        )))
        .ok();

        let cancel = self.cancel.clone();
        thread::spawn(move || run_job(tx, input, output, cfg, cancel));

    }

    /// Poll the worker channel and update the UI state.
    fn poll(&mut self) {
    let Some(rx) = self.rx.take() else { return; };

    let mut done = false;

    while let Ok(msg) = rx.try_recv() {
        match msg {
            Msg::Log(s) => self.log.push(s),
            Msg::Done(res) => {
                self.running = false;
                done = true;
                match res {
                    Ok(r) => self.last_report = Some(r),
                    Err(e) => self.last_error = Some(format!("{:#}", e)),
                }
            }
            Msg::Progress(ev) => {
                match ev {
                    pcap_ts_core::ExtractEvent::Frame { frames_total, udp_matched } => {
                        self.log.push(format!(
                            "Frames={} UDP matched={}",
                            frames_total, udp_matched
                        ));
                    
                    
                    }
                    pcap_ts_core::ExtractEvent::DetectedPacketSize { size } => {
                        self.log.push(format!("Detected TS packet size: {}", size));
                    }
                    pcap_ts_core::ExtractEvent::WrittenPackets { ts_packets_written } => {
                        self.log.push(format!("TS packets written: {}", ts_packets_written));
                    }
                }
            }

        }
        if done {
            break;
        }
    }

    // Put the receiver back only if we are still running and want to keep listening.
    if !done {
        self.rx = Some(rx);
    }
}

}

/// Worker entrypoint for running extraction off the UI thread.
fn run_job(
    tx: Sender<Msg>,
    input: PathBuf,
    output: Option<PathBuf>,
    cfg: pcap_ts_core::ExtractConfig,
    cancel: Arc<AtomicBool>,
) {
    let res = pcap_ts_core::extract_pcap_to_ts_with_events(
        &input,
        output.as_deref(),
        &cfg,
        &cancel,
        |ev| {
            tx.send(Msg::Progress(ev)).ok();
        },
    );

    tx.send(Msg::Done(res)).ok();
}


impl eframe::App for DesktopApp {
    /// Render the UI and handle interactions.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("pcap_ts_extract (Desktop)");

            ui.separator();

            // File pickers
            ui.horizontal(|ui| {
                if ui.button("Choose PCAP/PCAPNG.").clicked() && !self.running {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("PCAP", &["pcap", "pcapng", "pcap1"])
                        .pick_file()
                    {
                        self.input = Some(p);
                    }
                }
                ui.label(
                    self.input
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "No input selected".into()),
                );
            });

            ui.horizontal(|ui| {
                ui.add_enabled_ui(!self.dry_run, |ui| {
                    if ui.button("Choose output .ts.").clicked() && !self.running {
                        if let Some(p) = rfd::FileDialog::new()
                            .set_file_name("output.ts")
                            .add_filter("Transport Stream", &["ts"])
                            .save_file()
                        {
                            self.output = Some(p);
                        }
                    }
                });

                let label = if self.dry_run {
                    "Dry run enabled (no output file)".to_string()
                } else {
                    self.output
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "No output selected".into())
                };
                ui.label(label);
            });

            ui.separator();

            // Options
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.strip_rtp, "Strip RTP");
                ui.checkbox(&mut self.dry_run, "Dry run");
                ui.add(egui::DragValue::new(&mut self.sync_checks).range(1..=20))
                    .on_hover_text("Sync checks (consecutive 0x47 syncs)");
                ui.label("sync checks");
            });

            ui.horizontal(|ui| {
                ui.label("dst port");
                port_editor(ui, &mut self.dst_port, self.running);

                ui.separator();

                ui.label("src port");
                port_editor(ui, &mut self.src_port, self.running);
            });

            ui.separator();

            // Start button
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!self.running, |ui| {
                    if ui.button("Start").clicked() {
                        self.start();
                    }
                });

                ui.add_enabled_ui(self.running, |ui| {
                    if ui.button("Cancel").clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                });

                if self.running {
                    ui.label("Running.");
                }
            });

            // Results
            if let Some(err) = &self.last_error {
                ui.colored_label(egui::Color32::RED, err);
            }

            if let Some(r) = &self.last_report {
                ui.separator();
                ui.label(format!("PCAP frames seen:            {}", r.frames_total));
                ui.label(format!("UDP frames matched filters:  {}", r.udp_matched));
                ui.label(format!("TS packet size detected:     {}", r.detected_ts_packet_size));
                ui.label(format!("TS packets written:          {}", r.ts_packets_written));
                if let Some(out) = &r.output {
                    ui.label(format!("Output: {}", out.display()));
                } else {
                    ui.label("Output: (dry run)");
                }
                ui.label(format!(
                    "Elapsed: {}.{:03}s",
                    r.elapsed.as_secs(),
                    r.elapsed.subsec_millis()
                ));
            }

            ui.separator();
            ui.label("Log:");
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for line in &self.log {
                    ui.monospace(line);
                }
            });
        });

        // keep UI responsive
        ctx.request_repaint();
    }
}

/// Port editor for optional UDP port filters.
fn port_editor(ui: &mut egui::Ui, port: &mut Option<u16>, running: bool) {
    // We use a temporary i32 for the widget, because Option<u16> doesn't directly bind.
    let mut val: i32 = port.map(|p| p as i32).unwrap_or(-1);
    ui.add_enabled_ui(!running, |ui| {
        ui.add(egui::DragValue::new(&mut val).range(-1..=65535))
            .on_hover_text("-1 means disabled; otherwise set UDP port filter");
        if val < 0 {
            *port = None;
        } else {
            *port = Some(val as u16);
        }
    });
}

/// Entrypoint for desktop mode.
fn main() -> eframe::Result<()> {
    let mut opts = eframe::NativeOptions::default();

    if let Some(icon) = load_app_icon() {
        opts.viewport = opts.viewport.with_icon(icon);
    }

    eframe::run_native(
        "pcap_ts_extract (Desktop)",
        opts,
        Box::new(|_cc| Ok(Box::new(DesktopApp::default()))),
    )
}


/// Load the embedded application icon (PNG, 256x256) for window/taskbar use.
fn load_app_icon() -> Option<egui::IconData> {
    // Embedded at compile-time to avoid filesystem/runtime issues.
    let icon_bytes = include_bytes!("../../../resources/PCAPtoTS - SQ - 256.png");
    let image = image::load_from_memory(icon_bytes).ok()?;
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();

    Some(egui::IconData {
        rgba: rgba.into_raw(),
        width,
        height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_consistent() {
        let app = DesktopApp::default();
        assert!(app.input.is_none());
        assert!(app.output.is_none());
        assert!(app.dst_port.is_none());
        assert!(app.src_port.is_none());
        assert!(app.strip_rtp);
        assert_eq!(app.sync_checks, 3);
        assert!(!app.dry_run);
        assert!(!app.running);
        assert!(app.rx.is_none());
        assert!(app.log.is_empty());
        assert!(app.last_report.is_none());
        assert!(app.last_error.is_none());
    }

    #[test]
    fn embedded_icon_decodes() {
        let icon = load_app_icon();
        assert!(icon.is_some());
    }
}
