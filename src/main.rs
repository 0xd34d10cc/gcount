#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use chrono::{NaiveDate, Utc};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static GCOUNT: AtomicUsize = AtomicUsize::new(0);

fn atomic_take(value: &AtomicUsize) -> usize {
    let mut val = value.load(Ordering::SeqCst);
    if val != 0 {
        loop {
            match value.compare_exchange_weak(val, 0, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(new_val) => val = new_val,
            }
        }
    }

    val
}

fn active_exe() -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

    unsafe {
        let window = GetForegroundWindow();
        if window.0 == 0 {
            return None;
        }

        let mut process_id = 0;
        GetWindowThreadProcessId(window, Some(&mut process_id));
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id).ok()?;
        let mut buffer = [0u16; 1024];
        let n = K32GetProcessImageFileNameW(process, &mut buffer) as usize;
        CloseHandle(process);

        let name = &buffer[..n];
        Some(String::from_utf16_lossy(name))
    }
}

fn monitor_activity(active: &AtomicBool, exe_name: &str) {
    loop {
        if let Some(active_exe) = active_exe() {
            let is_active = active_exe.ends_with(exe_name);
            active.store(is_active, Ordering::SeqCst);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[derive(Default, Serialize, Deserialize)]
struct GCount {
    counts: HashMap<NaiveDate, usize>,
}

impl GCount {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        context
            .storage
            .and_then(|storage| eframe::get_value(storage, "gcount"))
            .unwrap_or_default()
    }
}

impl eframe::App for GCount {
    /// Called by the frame work to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "gcount", self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let clicks = atomic_take(&GCOUNT);
        if clicks != 0 {
            let today = Utc::now().naive_utc().date();
            let count = self.counts.entry(today).or_insert(0);
            *count += clicks;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            for (date, count) in self.counts.iter() {
                ui.label(format!("{}: {}", date, count));
            }
        });
    }
}

fn main() {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    // tracing_subscriber::fmt::init();

    inputbot::KeybdKey::GKey.bind(|| {
        if ACTIVE.load(Ordering::SeqCst) {
            GCOUNT.fetch_add(1, Ordering::SeqCst);
        }
    });

    std::thread::spawn(inputbot::handle_input_events);
    std::thread::spawn(|| monitor_activity(&ACTIVE, "LOSTARK.exe"));

    let options = eframe::NativeOptions::default();
    eframe::run_native("GCount", options, Box::new(|cc| Box::new(GCount::new(cc))));
}
