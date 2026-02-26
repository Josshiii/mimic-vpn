use std::net::UdpSocket;
use std::process::Command;
use std::sync::{Arc, Mutex}; // Necesitamos Mutex para compartir datos
use std::thread;
use std::time::{Duration, Instant}; // Para medir el tiempo (Ping)
use tauri::Emitter;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; // Mensaje secreto de latido

// --- FUNCIONES DE RED ---

// 1. HILO DE SALIDA (Tráfico de Juego)
fn iniciar_hilo_salida<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, ip_amigo: String, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        loop {
            match session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    if bytes.len() > 0 {
                        enviar_paquete_seguro(&socket, &ip_amigo, bytes, &cipher);
                        let _ = app_handle.emit("trafico-salida", bytes.len());
                    }
                },
                Err(_) => break, 
            }
        }
    });
}

// 2. HILO DE LATIDO (Keep-Alive & Ping) - NUEVO 💓
// Envía un paquete vacío cada 2 segundos para mantener el router abierto
fn iniciar_hilo_latido<R: tauri::Runtime>(socket: UdpSocket, ip_amigo: String, cipher: Arc<ChaCha20Poly1305>) {
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            // Enviamos el latido encriptado (para que parezca tráfico real)
            enviar_paquete_seguro(&socket, &ip_amigo, HEARTBEAT_MSG, &cipher);
        }
    });
}

// Función auxiliar para encriptar y enviar (reutilizable)
fn enviar_paquete_seguro(socket: &UdpSocket, destino: &str, datos: &[u8], cipher: &ChaCha20Poly1305) {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    if let Ok(encrypted_msg) = cipher.encrypt(nonce, datos) {
        let mut final_packet = nonce_bytes.to_vec();
        final_packet.extend_from_slice(&encrypted_msg);
        let _ = socket.send_to(&final_packet, destino);
    }
}

// 3. HILO DE ENTRADA (Recibir y Clasificar)
fn iniciar_hilo_entrada<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                if size > 12 {
                    let nonce = Nonce::from_slice(&buffer[..12]);
                    let ciphertext = &buffer[12..size];

                    if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
                        
                        // ¿ES UN LATIDO? 💓
                        if decrypted == HEARTBEAT_MSG {
                            // No lo mandamos al adaptador (Windows no sabría qué hacer con él)
                            // Solo avisamos al Frontend: "¡Llegó un latido!"
                            let _ = app_handle.emit("evento-ping", ());
                        } 
                        // ¿ES TRÁFICO REAL? 🎮
                        else {
                            if let Ok(mut packet) = session.allocate_send_packet(decrypted.len() as u16) {
                                packet.bytes_mut().copy_from_slice(&decrypted);
                                session.send_packet(packet);
                                let _ = app_handle.emit("trafico-entrada", size);
                            }
                        }
                    }
                }
            }
        }
    });
}

// --- COMANDO PRINCIPAL ---
#[tauri::command]
fn conectar_tunel(ip_destino: String, puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    
    let key_bytes = match general_purpose::STANDARD.decode(&clave_b64) {
        Ok(k) => k, Err(_) => return "Clave inválida".to_string(),
    };
    if key_bytes.len() != 32 { return "Longitud de clave incorrecta".to_string(); }

    let key = Key::from_slice(&key_bytes);
    let cipher = Arc::new(ChaCha20Poly1305::new(key));

    let wintun = unsafe { wintun::load_from_path("wintun.dll") };
    if wintun.is_err() { return "Falta wintun.dll".to_string(); }
    let wintun = wintun.unwrap();

    let adapter = match wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None) {
        Ok(a) => a, Err(_) => return "Error creando adaptador".to_string(),
    };

    let session = match adapter.start_session(0x400000) {
        Ok(s) => s, Err(e) => return format!("Error sesión: {:?}", e),
    };

    let _ = Command::new("netsh").args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK]).output();

    let socket_local = match UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)) {
        Ok(s) => s, Err(e) => return format!("Puerto ocupado: {}", e),
    };
    
    // Hole Punching Inicial
    let _ = socket_local.send_to(b"HELLO_NAT", &ip_destino);

    let session_arc = Arc::new(session);

    // Lanzamos los 3 Hilos: Entrada, Salida y Latido
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    iniciar_hilo_salida(session_arc, socket_local.try_clone().unwrap(), ip_destino.clone(), cipher.clone(), app_handle.clone());
    iniciar_hilo_latido(socket_local, ip_destino, cipher);

    format!("ENLACE ACTIVO CON: {}", ip_destino)
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
