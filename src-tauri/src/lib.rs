use std::net::UdpSocket;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::Emitter;
use tungstenite::{connect, Message};
use url::Url;
use std::time::Duration;

// --- LIBRERÍAS DE SEGURIDAD ---
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // El algoritmo
use chacha20poly1305::aead::{Aead, NewAead}; // Funciones de encriptar
use rand::{Rng, RngCore}; // Generador de aleatoriedad
use base64::{Engine as _, engine::general_purpose}; // Para enviar claves en texto

// CONFIGURACIÓN
const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
// Asegúrate de que esta sea TU URL de Render
const SERVER_URL: &str = "wss://mimic-signal.onrender.com"; 

// --- FUNCIONES DE TÚNEL SEGURO ---

// 🔒 Hilo de SALIDA (PC -> INTERNET)
// Encripta todo lo que sale de tu adaptador antes de enviarlo
fn iniciar_hilo_salida<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket, 
    ip_amigo: String, 
    cipher: Arc<ChaCha20Poly1305>, // <--- Nuestra máquina de encriptación
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        loop {
            if let Ok(packet) = session.receive_blocking() {
                let bytes = packet.bytes();
                if bytes.len() > 0 {
                    // 1. Generar un Nonce (Número único para este paquete)
                    // Esto evita ataques de "Replay"
                    let mut nonce_bytes = [0u8; 12];
                    rand::thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);

                    // 2. 🔒 ENCRIPTAR EL PAQUETE
                    // Si falla la encriptación, ignoramos el paquete (no debería pasar)
                    if let Ok(encrypted_msg) = cipher.encrypt(nonce, bytes) {
                        
                        // 3. Empaquetar: [NONCE (12 bytes)] + [DATOS ENCRIPTADOS]
                        // El receptor necesita el Nonce para desencriptar, se envía en claro (no es secreto)
                        let mut final_packet = nonce_bytes.to_vec();
                        final_packet.extend_from_slice(&encrypted_msg);

                        // 4. Enviar bala blindada a internet
                        let _ = socket.send_to(&final_packet, &ip_amigo);
                        let _ = app_handle.emit("trafico-salida", bytes.len());
                    }
                }
            } else { break; }
        }
    });
}

// 🔓 Hilo de ENTRADA (INTERNET -> PC)
// Desencripta lo que llega y lo verifica
fn iniciar_hilo_entrada<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket, 
    cipher: Arc<ChaCha20Poly1305>, // <--- Nuestra máquina de desencriptación
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                // El paquete debe tener al menos 12 bytes (Nonce) + 1 byte de datos
                if size > 12 {
                    let datos_recibidos = &buffer[..size];
                    
                    // 1. Separar el Nonce de los Datos
                    let nonce_bytes = &datos_recibidos[..12];
                    let ciphertext = &datos_recibidos[12..];
                    let nonce = Nonce::from_slice(nonce_bytes);

                    // 2. 🔓 DESENCRIPTAR Y VERIFICAR
                    // Si alguien manipuló el paquete en internet, esto fallará automáticamente
                    match cipher.decrypt(nonce, ciphertext) {
                        Ok(decrypted_data) => {
                            // Éxito: Escribir en el adaptador virtual
                            if let Ok(mut packet) = session.allocate_send_packet(decrypted_data.len() as u16) {
                                packet.bytes_mut().copy_from_slice(&decrypted_data);
                                session.send_packet(packet);
                                let _ = app_handle.emit("trafico-entrada", size);
                            }
                        },
                        Err(_) => {
                            // 🚨 ALERTA: Paquete corrupto o ataque detectado. Se descarta silenciosamente.
                            println!("Paquete inválido o ataque detectado. Descartado.");
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
    
    // 1. Decodificar la Llave Maestra (Viene del WebSocket)
    let key_bytes = match general_purpose::STANDARD.decode(&clave_b64) {
        Ok(k) => k,
        Err(_) => return "Error: Clave de seguridad inválida".to_string(),
    };

    if key_bytes.len() != 32 {
        return "Error: La clave debe ser de 32 bytes".to_string();
    }

    // 2. Iniciar el Motor de Encriptación
    let key = Key::from_slice(&key_bytes);
    let cipher = Arc::new(ChaCha20Poly1305::new(key));

    // 3. Configuración estándar de red (Wintun)
    let wintun = unsafe { wintun::load_from_path("wintun.dll") };
    if wintun.is_err() { return "Falta wintun.dll".to_string(); }
    let wintun = wintun.unwrap();

    let adapter = match wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None) {
        Ok(a) => a,
        Err(_) => return "Error creando adaptador (¿Eres Admin?)".to_string(),
    };

    let session = adapter.start_session(0x400000).unwrap();

    let _ = Command::new("netsh")
        .args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK])
        .output();

    let socket_local = match UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)) {
        Ok(s) => s,
        Err(e) => return format!("Puerto ocupado: {}", e),
    };
    
    // HOLE PUNCHING (Ahora enviamos basura encriptada para abrir el puerto)
    let _ = socket_local.send_to(b"HOLA_NAT", &ip_destino);

    // 4. Lanzar Hilos con Seguridad Activada
    iniciar_hilo_entrada(Arc::new(session), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    iniciar_hilo_salida(Arc::new(session), socket_local, ip_destino.clone(), cipher, app_handle);

    format!("CONEXIÓN SEGURA ACTIVA: {}", ip_destino)
}

// Genera una clave segura de 32 bytes para la sesión
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
