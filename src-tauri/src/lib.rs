use tauri::Emitter;

// CÓDIGO SEGURO - MODO SIMULACIÓN
// Este código NO toca el sistema operativo. Si esto falla, es tu Hardware.

#[tauri::command]
fn conectar_tunel(_ip_destino: String, _puerto_local: String, _app_handle: tauri::AppHandle) -> String {
    // En lugar de cargar el driver, solo fingimos que lo hacemos.
    println!("MODO SEGURO: Fingiendo conexión...");
    "SIMULACIÓN: Túnel virtual activo (Sin driver real)".to_string()
}

#[tauri::command]
fn probar_driver() -> String {
    "Driver desactivado por seguridad".to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            conectar_tunel,
            probar_driver
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}