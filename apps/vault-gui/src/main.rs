// Vaultkeep desktop GUI. See docs/02-architecture.md and docs/13-gui.md.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use state::AppState;

fn main() {
    let app_state = AppState::new();
    app_state.spawn_idle_watchdog();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
            commands::vault_path_display,
            commands::is_unlocked,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::change_master_password,
            commands::list_entries,
            commands::search_entries,
            commands::get_entry,
            commands::add_entry,
            commands::edit_entry,
            commands::remove_entry,
            commands::generate_password,
            commands::check_all,
            commands::totp_code,
            commands::audit_log,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Vaultkeep GUI");
}
