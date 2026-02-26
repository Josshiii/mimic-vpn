use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use tauri::Emitter;

// --- LIBRERÍAS DE SEGURIDAD ---
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 

// CONFIGURACIÓN
const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";

// --- FUNCIONES DE TÚNEL SEGURO ---

// 🔒 Hilo de SALIDA (PC -> INTERNET)
fn iniciar_hilo_salida<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket, 
    ip_amigo: String, 
    cipher: Arc<ChaCha20Poly1305>, 
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        loop {
            // Usamos receive_blocking para esperar paquetes del sistema
            match session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    if bytes.len() > 0 {
                        // 1. Generar Nonce único
                        let mut nonce_bytes = [0u8; 12];
                        rand::thread_rng().fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        // 2. 🔒 ENCRIPTAR
                        if let Ok(encrypted_msg) = cipher.encrypt(nonce, bytes) {
                            
                            // 3. Empaquetar: [NONCE] + [DATOS]
                            let mut final_packet = nonce_bytes.to_vec();
                            final_packet.extend_from_slice(&encrypted_msg);

                            // 4. Enviar
                            let _ = socket.send_to(&final_packet, &ip_amigo);
                            let _ = app_handle.emit("trafico-salida", bytes.len());
                        }
                    }
                },
                Err(_) => break, // Si falla la sesión, salimos del hilo
            }
        }
    });
}

// 🔓 Hilo de ENTRADA (INTERNET -> PC)
fn iniciar_hilo_entrada<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket, 
    cipher: Arc<ChaCha20Poly1305>, 
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                if size > 12 {
                    let datos_recibidos = &buffer[..size];
                    
                    // 1. Separar Nonce y Datos
                    let nonce_bytes = &datos_recibidos[..12];
                    let ciphertext = &datos_recibidos[12..];
                    let nonce = Nonce::from_slice(nonce_bytes);

                    // 2. 🔓 DESENCRIPTAR
                    if let Ok(decrypted_data) = cipher.decrypt(nonce, ciphertext) {
                        // Éxito: Escribir en adaptador virtual
                        if let Ok(mut packet) = session.allocate_send_packet(decrypted_data.len() as u16) {
                            packet.bytes_mut().copy_from_slice(&decrypted_data);
                            session.send_packet(packet);
                            let _ = app_handle.emit("trafico-entrada", size);
                        }
                    }
                }
            }
        }
    });
}

// --- LÓGICA DE CONEXIÓN ---

#[tauri::command]
fn conectar_tunel(ip_destino: String, puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    
    // 1. Decodificar la Llave Maestra
    let key_bytes = match general_purpose::STANDARD.decode(&clave_b64) {
        Ok(k) => k,
        Err(_) => return "Error: Clave inválida (Base64 incorrecto)".to_string(),
    };

    if key_bytes.len() != 32 {
        return format!("Error: La clave debe ser de 32 bytes (Recibidos: {})", key_bytes.len());
    }

    // 2. Iniciar Motor de Encriptación
    let key = Key::from_slice(&key_bytes);
    let cipher = Arc::new(ChaCha20Poly1305::new(key));

    // 3. Configurar Wintun
    let wintun = unsafe { wintun::load_from_path("wintun.dll") };
    if wintun.is_err() { return "Falta wintun.dll".to_string(); }
    let wintun = wintun.unwrap();

    let adapter = match wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None) {
        Ok(a) => a,
        Err(_) => return "Error creando adaptador (Necesitas ser Admin)".to_string(),
    };

    let session = match adapter.start_session(0x400000) {
        Ok(s) => s,
        Err(e) => return format!("Error iniciando sesión Wintun: {:?}", e),
    };

    let _ = Command::new("netsh")
        .args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK])
        .output();

    let socket_local = match UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)) {
        Ok(s) => s,
        Err(e) => return format!("Puerto local {} ocupado: {}", puerto_local, e),
    };
    
    // Hole Punching Seguro
    // Enviamos basura, pero el otro extremo la descartará al no poder desencriptarla.
    // Esto es bueno: solo paquetes válidos pasan.
    let _ = socket_local.send_to(b"HOLA_NAT_SECURE_INIT", &ip_destino);

    // 4. Lanzar Hilos (CORRECCIÓN AQUÍ)
    // Envolvemos la sesión en un Arc UNA SOLA VEZ
    let session_arc = Arc::new(session);

    // Repartimos clones del Arc (barato y seguro)
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    iniciar_hilo_salida(session_arc, socket_local, ip_destino.clone(), cipher, app_handle);

    format!("ENLACE SEGURO ACTIVO CON: {}", ip_destino)
}

#[tauri::command]
fn generar_clave_segura() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    general_purpose::STANDARD.encode(key)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![conectar_tunel, generar_clave_segura])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
