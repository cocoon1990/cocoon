//! SCP-GHOST desktop shell.
//!
//! This binary is deliberately thin: it is a **controller**, not a proxy.
//! All networking is delegated to the battle-tested `meow` core (mihomo
//! compatible) which ships next to the executable as a Tauri sidecar.
//!
//! Responsibilities:
//!   * write the generated YAML to the app data directory
//!   * start / stop the sidecar and stream its logs to the UI
//!   * expose the updater (tauri-plugin-updater) to the frontend

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Manager, RunEvent, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_updater::UpdaterExt;

/// Sidecar base name — must match `bundle.externalBin` in tauri.conf.json.
const SIDECAR: &str = "meow";
/// Keep the UI log panel bounded.
const LOG_LIMIT: usize = 400;

#[derive(Default)]
struct Runtime {
    child: Option<CommandChild>,
    mode: String,
}

impl Runtime {
    fn kill(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = child.kill();
        }
        self.mode.clear();
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
    mode: String,
    version: String,
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

fn status(app: &AppHandle, running: bool, mode: String) -> CoreStatus {
    CoreStatus {
        running,
        mode,
        version: app.package_info().version.to_string(),
    }
}

fn current_state(app: &AppHandle, shared: &State<'_, Shared>) -> CoreStatus {
    let guard = match shared.0.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    status(app, guard.child.is_some(), guard.mode.clone())
}

#[tauri::command]
fn core_state(app: AppHandle, shared: State<'_, Shared>) -> CoreStatus {
    current_state(&app, &shared)
}

#[tauri::command]
fn start_core(
    app: AppHandle,
    shared: State<'_, Shared>,
    logs: State<'_, LogBuffer>,
    config: String,
    mode: String,
) -> Result<CoreStatus, String> {
    let mode = if mode == "proxy" { "proxy" } else { "tun" }.to_string();

    {
        let mut guard = match shared.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.kill();
    }

    let home = app
        .path()
        .app_local_data_dir()
        .map_err(|err| format!("cannot resolve app data directory: {err}"))?
        .join("core");
    std::fs::create_dir_all(&home)
        .map_err(|err| format!("cannot create {}: {err}", home.display()))?;

    let config_path = home.join("config.yaml");
    std::fs::write(&config_path, config.as_bytes())
        .map_err(|err| format!("cannot write {}: {err}", config_path.display()))?;

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

    let buffer = logs.inner().clone();
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

    {
        let mut guard = match shared.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.mode = mode.clone();
        guard.child = Some(child);
    }

    Ok(status(&app, true, mode))
}

#[tauri::command]
fn stop_core(app: AppHandle, shared: State<'_, Shared>) -> Result<CoreStatus, String> {
    {
        let mut guard = match shared.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.kill();
    }
    Ok(status(&app, false, String::new()))
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
            read_logs,
            clear_logs,
            check_updates,
            install_update
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the SCP-GHOST shell")
        .run(|app, event| {
            if matches!(event, RunEvent::Exit) {
                if let Some(shared) = app.try_state::<Shared>() {
                    if let Ok(mut guard) = shared.0.lock() {
                        guard.kill();
                    }
                }
            }
        });
}
