// جلوگیری از باز شدن پنجرهٔ کنسول در نسخهٔ release ویندوز
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! main.rs — SCP-GHOST Desktop (Tauri v2) — **controller only**
//!
//! این crate هیچ کد شبکه، TUN، سوکت، TLS یا رمزنگاری ندارد. تمام آن کارها
//! به هستهٔ پراکسی (sidecar) سپرده شده است. وظیفهٔ این فایل فقط:
//!
//!   1. دریافت متن اشتراک (HTTP GET ساده — تا CORS گریبان webview را نگیرد)
//!   2. نوشتن کانفیگ YAML تولیدشده روی دیسک
//!   3. اجرا/توقف sidecar و جمع‌آوری لاگ آن
//!
//! تبدیل «URI → YAML» در `src/core-config.js` است تا با آزمون واحد واقعی
//! پوشش داده شود؛ logic سنگینی در Rust نمانده باشد.

use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::{Manager, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// نام sidecar — همان نامی که در `bundle.externalBin` آمده است.
const SIDECAR_NAME: &str = "meow";

/// فاصلهٔ ثبتی که هستهٔ ما با آن بالا می‌آید (mixed-port).
const MIXED_PORT: u16 = 7890;

/// سقف حجم اشتراک (۲۵۶ کیلوبایت) تا پاسخ‌های عجیب حافظه را نخورند.
const MAX_SUBSCRIPTION_BYTES: u64 = 256 * 1024;

/// حداکثر خطوط لاگ نگه‌داری‌شده در حافظه.
const MAX_LOG_LINES: usize = 400;

// ══════════════════════════════════════════════════════════════
//  وضعیت برنامه
// ══════════════════════════════════════════════════════════════

struct CoreProcess {
    /// با `kill_on_drop(true)` ساخته می‌شود؛ پس Drop همین دسته، فرایند را
    /// می‌کشد و هیچ meow.exe یتیمی نمی‌ماند.
    child: CommandChild,
    mode: String,
    config_path: String,
    pid: u32,
}

#[derive(Default)]
struct AppState {
    core: Mutex<Option<CoreProcess>>,
    log: Mutex<Vec<String>>,
}

type Shared = std::sync::Arc<AppState>;

// ══════════════════════════════════════════════════════════════
//  DTO
// ══════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreStatus {
    running: bool,
    mode: Option<String>,
    pid: Option<u32>,
    config_path: Option<String>,
    proxy_url: String,
    log: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionPayload {
    body: String,
    bytes: usize,
    status: u16,
}

// ══════════════════════════════════════════════════════════════
//  ابزار
// ══════════════════════════════════════════════════════════════

fn push_log(shared: &Shared, line: &str) {
    let cleaned = line.trim_end();
    if cleaned.is_empty() {
        return;
    }
    if let Ok(mut log) = shared.log.lock() {
        for part in cleaned.lines() {
            log.push(part.to_string());
        }
        if log.len() > MAX_LOG_LINES {
            let drop_count = log.len() - MAX_LOG_LINES;
            log.drain(0..drop_count);
        }
    }
}

fn snapshot(shared: &Shared) -> CoreStatus {
    let (running, mode, pid, config_path) = match shared.core.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(core) => (
                true,
                Some(core.mode.clone()),
                Some(core.pid),
                Some(core.config_path.clone()),
            ),
            None => (false, None, None, None),
        },
        Err(_) => (false, None, None, None),
    };

    let log = shared
        .log
        .lock()
        .map(|lines| lines.iter().rev().take(120).rev().cloned().collect())
        .unwrap_or_default();

    CoreStatus {
        running,
        mode,
        pid,
        config_path,
        proxy_url: format!("http://127.0.0.1:{MIXED_PORT}"),
        log,
    }
}

fn ensure_scheme(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        Ok(())
    } else {
        Err("آدرس اشتراک باید با http:// یا https:// شروع شود.".to_string())
    }
}

// ══════════════════════════════════════════════════════════════
//  دستورها
// ══════════════════════════════════════════════════════════════

/// متن اشتراک را از سرور می‌خواند (بدون هیچ پردازشی).
///
/// دریافت در Rust انجام می‌شود تا webview درگیر CORS نشود و بتوان
/// کدهای خطای HTTP را با پیام واقعی سرور به کاربر نشان داد.
#[tauri::command]
async fn fetch_subscription(url: String) -> Result<SubscriptionPayload, String> {
    tauri::async_runtime::spawn_blocking(move || {
        ensure_scheme(&url)?;

        let response = match ureq::get(&url)
            .timeout(Duration::from_secs(20))
            .set("Accept", "*/*")
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(code, response)) => {
                let mut detail = String::new();
                let _ = response
                    .into_reader()
                    .take(4096)
                    .read_to_string(&mut detail);
                return Err(format!(
                    "اشتراک با کد HTTP {code} پاسخ داد: {}",
                    detail.trim()
                ));
            }
            Err(err) => return Err(format!("دسترسی به آدرس اشتراک ممکن نشد: {err}")),
        };

        let status = response.status();
        let mut body = String::new();
        response
            .into_reader()
            .take(MAX_SUBSCRIPTION_BYTES)
            .read_to_string(&mut body)
            .map_err(|e| format!("خواندن پاسخ اشتراک ناموفق بود: {e}"))?;

        if body.trim().is_empty() {
            return Err("پاسخ اشتراک خالی بود.".to_string());
        }

        Ok(SubscriptionPayload {
            bytes: body.len(),
            status,
            body,
        })
    })
    .await
    .map_err(|e| format!("fetch task failed: {e}"))?
}

/// کانفیگ YAML را می‌نویسد و هسته را اجرا می‌کند.
#[tauri::command]
async fn start_core(
    app: tauri::AppHandle,
    state: State<'_, Shared>,
    config: String,
    mode: String,
) -> Result<CoreStatus, String> {
    let shared = std::sync::Arc::clone(state.inner());

    if shared
        .core
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
    {
        return Err("هسته از قبل در حال اجراست؛ اول قطع کنید.".to_string());
    }

    if config.trim().is_empty() || !config.contains("proxies:") {
        return Err("کانفیگ تولیدشده معتبر نیست.".to_string());
    }

    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("مسیر دادهٔ برنامه پیدا نشد: {e}"))?;
    let core_home = data_dir.join("core");
    let config_path = core_home.join("config.yaml");

    std::fs::create_dir_all(&core_home)
        .map_err(|e| format!("ساخت پوشهٔ کانفیگ ناموفق بود: {e}"))?;
    std::fs::write(&config_path, config.as_bytes())
        .map_err(|e| format!("نوشتن کانفیگ ناموفق بود: {e}"))?;

    let config_arg = config_path
        .to_str()
        .ok_or_else(|| "مسیر کانفیگ قابل تبدیل به رشته نیست.".to_string())?
        .to_string();
    let home_arg = core_home
        .to_str()
        .ok_or_else(|| "مسیر home قابل تبدیل به رشته نیست.".to_string())?
        .to_string();

    if let Ok(mut log) = shared.log.lock() {
        log.clear();
    }
    push_log(&shared, &format!("[app] mode={mode} config={config_arg}"));

    let args: Vec<String> = vec![
        "-d".to_string(),
        home_arg,
        "-f".to_string(),
        config_arg.clone(),
    ];

    let command = app
        .shell()
        .sidecar(SIDECAR_NAME)
        .map_err(|e| format!("sidecar «{SIDECAR_NAME}» پیدا نشد: {e}"))?
        .args(args)
        .kill_on_drop(true);

    let (mut rx, child) = command
        .spawn()
        .map_err(|e| format!("اجرای هستهٔ پراکسی ناموفق بود: {e}"))?;

    let pid = child.pid();
    push_log(&shared, &format!("[app] core started (pid {pid})"));

    {
        let mut guard = shared
            .core
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        *guard = Some(CoreProcess {
            child,
            mode: mode.clone(),
            config_path: config_arg,
            pid,
        });
    }

    // حلقهٔ جمع‌آوری لاگ هسته
    let log_state = std::sync::Arc::clone(&shared);
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    push_log(&log_state, &text);
                }
                CommandEvent::Error(err) => {
                    push_log(&log_state, &format!("[core error] {err}"));
                }
                CommandEvent::Terminated(payload) => {
                    push_log(
                        &log_state,
                        &format!(
                            "[app] core exited (code {:?}, signal {:?})",
                            payload.code, payload.signal
                        ),
                    );
                    if let Ok(mut guard) = log_state.core.lock() {
                        *guard = None;
                    }
                    break;
                }
                _ => {}
            }
        }
    });

    Ok(snapshot(&shared))
}

#[tauri::command]
fn stop_core(state: State<'_, Shared>) -> Result<CoreStatus, String> {
    let shared = std::sync::Arc::clone(state.inner());

    let taken = shared
        .core
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .take();

    match taken {
        Some(core) => {
            let CoreProcess { child, pid, .. } = core;
            // kill(self) تا خروج فرایند کامل شود و بعد لاگ ثبت شود
            if let Err(err) = child.kill() {
                push_log(&shared, &format!("[app] core did not stop cleanly: {err}"));
            }
            push_log(&shared, &format!("[app] core stopped (pid {pid})"));
        }
        None => push_log(&shared, "[app] stop requested but core was not running"),
    }

    Ok(snapshot(&shared))
}

#[tauri::command]
fn core_status(state: State<'_, Shared>) -> CoreStatus {
    snapshot(state.inner())
}

// ══════════════════════════════════════════════════════════════
//  Entry point
// ══════════════════════════════════════════════════════════════

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(std::sync::Arc::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            fetch_subscription,
            start_core,
            stop_core,
            core_status
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the SCP-GHOST desktop app")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(shared) = app_handle.try_state::<Shared>() {
                    if let Ok(mut guard) = shared.core.lock() {
                        // Drop → kill، تا هیچ meow.exe یتیمی نماند
                        guard.take();
                    }
                }
            }
        });
}
