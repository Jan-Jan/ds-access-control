//! ODS PoC Tauri app library.
//!
//! Wires `AppState` (OrgService + chain config) into the Tauri builder,
//! registers all Tauri commands, and exposes the `run()` entry point.

pub mod commands;
pub mod state;

use tauri::Manager;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve the data dir from Tauri's path resolver (may return an
            // error on platforms without a standard app-data location).
            let tauri_data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/ods-poc"));

            let app_state = AppState::init(tauri_data_dir)
                .unwrap_or_else(|e| panic!("AppState init failed: {e}"));
            app.manage(app_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_persona,
            commands::create_organisation,
            commands::export_invite,
            commands::import_invite,
            commands::export_join_request,
            commands::import_join_request,
            commands::admit_member,
            commands::revoke_member,
            commands::list_personas,
            commands::list_orgs,
            commands::connection_status,
            commands::start_receiver,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
