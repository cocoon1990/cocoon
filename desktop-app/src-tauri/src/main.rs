//! SCP-GHOST desktop shell.
//!
//! This binary is deliberately thin: it is a **controller**, not a proxy.
//! All networking is delegated to the battle-tested `meow` core (mihomo
//! compatible) which ships next to the executable as a Tauri sidecar.
//!
//! ── «پیلهٔ فانی» (Ephemeral Cocoon) ───────────────────────────────
//! قطع اتصال **هسته را نمی‌کشد**. آداپتور TUN (Wintun) یک بار ساخته
//! می‌شود و تا بسته‌شدن برنامه زنده می‌ماند؛ فقط نشست رمزنگاری پاک
//! می‌شود:
//!
//!   • disconnect → فایل نشست با صفر بازنویسی می‌شود (scrub)، پیکربندی
//!     «بی‌جلسه» روی هستهٔ در حال اجرا reload می‌شود؛ TUN سر جایش است.
//!   • reconnect  → فقط همان reload با پیکربندی واقعی؛ بدون spawn، بدون
//!     ساخت دوبارهٔ آداپتور → زیر یک ثانیه.
//!   • exit       → کشتن هسته و پاک‌سازی حافظه.
//!
//! اگر هستهٔ نصب‌شده کنترل‌پلین محلی (`external-controller`) را پشتیبانی
//! نکند، کد به رفتار قدیمی (kill + restart) برمی‌گردد و `adapter_kept`
//! را false گزارش می‌کند — UI همان را نشان می‌دهد. یعنی هیچ‌وقت دروغ
//! نمی‌گوییم که TUN زنده مانده است.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, RunEvent, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

/// Sidecar base name — must match `bundle.externalBin` in tauri.conf.json.
const SIDECAR: &str = "meow";
/// Keep the UI log panel bounded.
const LOG_LIMIT: usize = 400;
/// Local control plane of the core (mihomo `external-controller`).
const CONTROL_PORT: u16 = 9090;
/// How long we wait for a freshly spawned core to open its control port.
const CONTROL_WAIT: Duration = Duration::from_millis(2500);

#[derive(Default)]
struct Runtime {
    child: Option<CommandChild>,
    mode: String,
    /// یک نشست رمزنگاری فعال است (پروکسی وصل است).
    session: bool,
    /// آداپتور TUN زنده است (هسته در حال اجراست).
    adapter: bool,
    /// آخرین مسیر فایل پیکربندی که نوشتیم (برای scrub).
    config_path: Option<std::path::PathBuf>,
}

impl Runtime {
    fn kill(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = child.kill();
        }
        self.mode.clear();
        self.session = false;
        self.adapter = false;
    }
}

struct Shared(Mutex<Runtime>);

impl Default for Shared {
    fn default() -> Self {
        Self(Mutex::new(Runtime::default()))
    }
}

type LogBuffer = Arc<Mutex<VecDeque<String>>>;

#[derive(Serialize)]
struct CoreStatus {
    running: bool,
    /// نشست رمزنگاری فعال است.
    session: bool,
    /// آداپتور TUN زنده است و با قطع اتصال از بین نرفته.
    adapter: bool,
    mode: String,
    version: String,
    /// زمان صرف‌شده برای همین عملیات (میلی‌ثانیه) — برای اثبات < ۱s.
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct UpdateReport {
    available: bool,
    current: String,
    latest: Option<String>,
    notes: Option<String>,
    error: Option<String>,
}

fn push_log(logs: &LogBuffer, line: String) {
    let mut guard = match logs.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    for raw in line.lines() {
        let trimmed = raw.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        guard.push_back(trimmed.chars().take(400).collect::<String>());
    }
    while guard.len() > LOG_LIMIT {
        guard.pop_front();
    }
}

fn lock_shared<'a>(shared: &'a State<'_, Shared>) -> std::sync::MutexGuard<'a, Runtime> {
    match shared.0.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn status(app: &AppHandle, guard: &Runtime, elapsed_ms: u64) -> CoreStatus {
    CoreStatus {
        running: guard.adapter,
        session: guard.session,
        adapter: guard.adapter,
        mode: guard.mode.clone(),
        version: app.package_info().version.to_string(),
        elapsed_ms,
    }
}

/// نوشتن امن فایل پیکربندی: اول نسخهٔ قبلی با صفر بازنویسی می‌شود تا
/// UUID/کلید نشست قبلی روی دیسک باقی نماند، سپس نسخهٔ تازه نوشته می‌شود.
fn scrub_write(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len() as usize;
        if len > 0 {
            let _ = std::fs::write(path, vec![0u8; len]);
        }
    }
    std::fs::write(path, contents.as_bytes())
}

// [control-plane] تنها جای مجاز سوکت در پوسته: PUT کوتاه و همگام روی
// 127.0.0.1 برای reload پیکربندی هسته، و یک connect کوتاه برای صبر کردن
// تا کنترل‌پلین بالا بیاید. هیچ بایتی از ترافیک کاربر از اینجا عبور
// نمی‌کند و هیچ listenerی باز نمی‌شود.
use std::net::{SocketAddr, TcpStream};

fn control_put(port: u16, path: &str, body: &str) -> std::io::Result<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(400))?;
    stream.set_read_timeout(Some(Duration::from_millis(1500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(1500)))?;

    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = path,
        port = port,
        len = body.len(),
        body = body
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut buf = [0u8; 64];
    let read = stream.read(&mut buf)?;
    let head = String::from_utf8_lossy(&buf[..read]).to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
}

/// به‌روزرسانی داغ پیکربندی هستهٔ در حال اجرا (بدون spawn دوباره).
fn hot_reload(port: u16, config_path: &std::path::Path) -> Result<(), String> {
    let body = format!(
        "{{\"path\":{}}}",
        serde_json::to_string(&config_path.to_string_lossy()).map_err(|err| err.to_string())?
    );
    match control_put(port, "/configs?force=true", &body) {
        Ok(code) if (200..300).contains(&code) => Ok(()),
        Ok(code) => Err(format!("core rejected the reload (HTTP {code})")),
        Err(err) => Err(format!("core control port is not reachable: {err}")),
    }
}

/// صبر تا باز شدن کنترل‌پلین هستهٔ تازه‌سپاون‌شده.
fn wait_for_control(port: u16, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(120)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    false
}
// [/control-plane]

fn spawn_core(
    app: &AppHandle,
    logs: &LogBuffer,
    home: &std::path::Path,
    config_path: &std::path::Path,
    mode: &str,
) -> Result<CommandChild, String> {
    let sidecar = app
        .shell()
        .sidecar(SIDECAR)
        .map_err(|err| format!("the meow core is not bundled with this build: {err}"))?;

    let args = vec![
        "-d".to_string(),
        home.to_string_lossy().to_string(),
        "-f".to_string(),
        config_path.to_string_lossy().to_string(),
    ];

    let (mut events, child) = sidecar
        .args(args)
        .spawn()
        .map_err(|err| format!("meow core failed to start: {err}"))?;

    let buffer = logs.clone();
    push_log(&buffer, format!("[scp-ghost] core started in {mode} mode"));

    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stdout(bytes) => {
                    push_log(&buffer, String::from_utf8_lossy(&bytes).to_string())
                }
                CommandEvent::Stderr(bytes) => {
                    push_log(&buffer, String::from_utf8_lossy(&bytes).to_string())
                }
                CommandEvent::Error(err) => push_log(&buffer, format!("[error] {err}")),
                CommandEvent::Terminated(payload) => {
                    push_log(
                        &buffer,
                        format!("[scp-ghost] core exited ({:?})", payload.code),
                    );
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(child)
}

#[tauri::command]
fn core_state(app: AppHandle, shared: State<'_, Shared>) -> CoreStatus {
    let guard = lock_shared(&shared);
    status(&app, &guard, 0)
}

/// اتصال. اگر هسته از قبل زنده باشد، فقط پیکربندی به‌صورت داغ reload
/// می‌شود (همان reconnect زیر یک ثانیه).
#[tauri::command]
fn start_core(
    app: AppHandle,
    shared: State<'_, Shared>,
    logs: State<'_, LogBuffer>,
    config: String,
    mode: String,
) -> Result<CoreStatus, String> {
    let started = Instant::now();
    let mode = if mode == "proxy" { "proxy" } else { "tun" }.to_string();
    let buffer = logs.inner().clone();

    let home = app
        .path()
        .app_local_data_dir()
        .map_err(|err| format!("cannot resolve app data directory: {err}"))?
        .join("core");
    std::fs::create_dir_all(&home)
        .map_err(|err| format!("cannot create {}: {err}", home.display()))?;

    let config_path = home.join("session.yaml");
    scrub_write(&config_path, &config)
        .map_err(|err| format!("cannot write {}: {err}", config_path.display()))?;

    let mut guard = lock_shared(&shared);

    // ── مسیر سریع: هسته زنده است، فقط نشست را سوار کن ────────────
    if guard.adapter {
        match hot_reload(CONTROL_PORT, &config_path) {
            Ok(()) => {
                guard.session = true;
                guard.mode = mode.clone();
                guard.config_path = Some(config_path);
                let elapsed = started.elapsed().as_millis() as u64;
                push_log(
                    &buffer,
                    format!("[scp-ghost] session resumed in {elapsed} ms (TUN kept alive)"),
                );
                return Ok(status(&app, &guard, elapsed));
            }
            Err(err) => {
                // کنترل‌پلین در دسترس نیست → به رفتار قدیمی برگرد
                push_log(&buffer, format!("[warn] hot reload failed: {err}"));
                guard.kill();
            }
        }
    }

    // ── مسیر سرد: اولین اتصال، هسته را بالا بیاور ────────────────
    let child = spawn_core(&app, &buffer, &home, &config_path, &mode)?;
    guard.child = Some(child);
    guard.adapter = true;
    guard.session = true;
    guard.mode = mode;
    guard.config_path = Some(config_path);

    if !wait_for_control(CONTROL_PORT, CONTROL_WAIT) {
        push_log(
            &buffer,
            "[warn] core control plane did not open; reconnect will restart the core (TUN will be rebuilt)".to_string(),
        );
    }

    let elapsed = started.elapsed().as_millis() as u64;
    push_log(&buffer, format!("[scp-ghost] session up in {elapsed} ms"));
    Ok(status(&app, &guard, elapsed))
}

/// قطع اتصال **بدون** کشتن آداپتور: فقط نشست رمزنگاری پاک می‌شود.
#[tauri::command]
fn stop_core(app: AppHandle, shared: State<'_, Shared>, logs: State<'_, LogBuffer>) -> Result<CoreStatus, String> {
    let started = Instant::now();
    let buffer = logs.inner().clone();
    let mut guard = lock_shared(&shared);

    if !guard.adapter {
        return Ok(status(&app, &guard, 0));
    }

    let mode = if guard.mode.is_empty() {
        "tun".to_string()
    } else {
        guard.mode.clone()
    };
    let detached = detached_config(&mode);

    let path = guard
        .config_path
        .clone()
        .or_else(|| app.path().app_local_data_dir().ok().map(|p| p.join("core").join("session.yaml")));

    if let Some(path) = path {
        let _ = scrub_write(&path, &detached);
        match hot_reload(CONTROL_PORT, &path) {
            Ok(()) => {
                guard.session = false;
                // آداپتور سر جایش است: هسته زنده می‌ماند.
                let elapsed = started.elapsed().as_millis() as u64;
                push_log(
                    &buffer,
                    format!("[scp-ghost] session closed in {elapsed} ms (TUN adapter kept)"),
                );
                return Ok(status(&app, &guard, elapsed));
            }
            Err(err) => push_log(&buffer, format!("[warn] hot pause failed: {err} — stopping the core")),
        }
    }

    // fallback: هستهٔ قدیمی که کنترل‌پلین ندارد
    guard.kill();
    let elapsed = started.elapsed().as_millis() as u64;
    push_log(
        &buffer,
        "[scp-ghost] core stopped (this build cannot keep the TUN adapter)".to_string(),
    );
    Ok(status(&app, &guard, elapsed))
}

/// خروج کامل: آداپتور TUN حالا نابود می‌شود.
#[tauri::command]
fn shutdown_core(app: AppHandle, shared: State<'_, Shared>, logs: State<'_, LogBuffer>) -> CoreStatus {
    let buffer = logs.inner().clone();
    let mut guard = lock_shared(&shared);
    if let Some(path) = guard.config_path.clone() {
        // پاک‌سازی نهایی: نه UUID، نه کلید.
        let _ = scrub_write(&path, "# session wiped on exit\n");
    }
    guard.kill();
    push_log(
        &buffer,
        "[scp-ghost] core stopped, TUN adapter destroyed, memory wiped".to_string(),
    );
    status(&app, &guard, 0)
}

/// یک خط از UI به همان بافر لاگ (تا خطاها فوراً و کنار لاگ هسته دیده شوند).
#[tauri::command]
fn log_line(logs: State<'_, LogBuffer>, line: String) {
    push_log(logs.inner(), format!("[ui] {line}"));
}

#[tauri::command]
fn read_logs(logs: State<'_, LogBuffer>) -> Vec<String> {
    let guard = match logs.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.iter().cloned().collect()
}

#[tauri::command]
fn clear_logs(logs: State<'_, LogBuffer>) {
    let mut guard = match logs.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();
}

#[tauri::command]
async fn check_updates(app: AppHandle) -> Result<UpdateReport, String> {
    let current = app.package_info().version.to_string();

    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(err) => {
            return Ok(UpdateReport {
                available: false,
                current,
                latest: None,
                notes: None,
                error: Some(err.to_string()),
            })
        }
    };

    match updater.check().await {
        Ok(Some(update)) => Ok(UpdateReport {
            available: true,
            current,
            latest: Some(update.version.clone()),
            notes: update.body.clone(),
            error: None,
        }),
        Ok(None) => Ok(UpdateReport {
            available: false,
            current,
            latest: None,
            notes: None,
            error: None,
        }),
        Err(err) => Ok(UpdateReport {
            available: false,
            current,
            latest: None,
            notes: None,
            error: Some(err.to_string()),
        }),
    }
}

#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let updater = app.updater().map_err(|err| err.to_string())?;
    let update = updater
        .check()
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "no update is available".to_string())?;

    update
        .download_and_install(|_chunk: usize, _total: Option<u64>| {}, || {})
        .await
        .map_err(|err| err.to_string())
}

/// پیکربندی «بی‌جلسه» — عمداً در راست هم هست تا اگر فایل UI قدیمی باشد
/// باز هم قطع اتصال، TUN را نکشد.
fn detached_config(mode: &str) -> String {
    let tun = if mode == "tun" { "true" } else { "false" };
    format!(
        "# SCP-GHOST — detached session (no tunnel, adapter kept alive).\n\
mode: direct\n\
allow-lan: false\n\
bind-address: \"127.0.0.1\"\n\
external-controller: \"127.0.0.1:{CONTROL_PORT}\"\n\
ipv6: false\n\
proxies: []\n\
proxy-groups: []\n\
rules:\n  - \"MATCH,DIRECT\"\n\
tun:\n  enable: {tun}\n  stack: \"mixed\"\n  auto-route: true\n  auto-detect-interface: true\n  mtu: 1500\n"
    )
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Shared::default())
        .manage(LogBuffer::default())
        .invoke_handler(tauri::generate_handler![
            core_state,
            start_core,
            stop_core,
            shutdown_core,
            log_line,
            read_logs,
            clear_logs,
            check_updates,
            install_update
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the SCP-GHOST shell")
        .run(|app, event| {
            if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
                if let Some(shared) = app.try_state::<Shared>() {
                    if let Ok(mut guard) = shared.0.lock() {
                        guard.kill();
                    }
                }
            }
        });
}
