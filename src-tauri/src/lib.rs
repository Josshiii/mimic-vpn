use std::net::UdpSocket;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::Emitter;
use std::os::windows::process::CommandExt; // Para ocultar ventanas de CMD

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; 
const CREATE_NO_WINDOW: u32 = 0x08000000; // Flag para que no salten ventanas negras

static PEERS_GLOBAL: Mutex<Vec<String>> = Mutex::new(Vec::new());

// --- UTILIDADES DEL SISTEMA ---

// Esta función convierte a Mimic Hub en el REY de la red
fn optimizar_windows(puerto: &str) {
    // 1. Abrir Firewall (Regla de entrada y salida para nuestro puerto)
    let _ = Command::new("netsh")
        .args(&["advfirewall", "firewall", "add", "rule", 
                &format!("name=\"MimicHub-UDP-{}\"", puerto), 
                "dir=in", "action=allow", "protocol=UDP", &format!("localport={}", puerto)])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    // 2. Dar Prioridad Máxima al Adaptador (Métrica 1 = La más alta)
    // Esto hace que los juegos busquen partidas aquí primero
    let _ = Command::new("powershell")
        .args(&["-Command", &format!(
            "Get-NetAdapter -Name '{}' | Set-NetIPInterface -InterfaceMetric 1", 
            NOMBRE_ADAPTADOR
        )])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

// --- AUXILIAR DE ENCRIPTACIÓN ---
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

// --- HILO DE ENTRADA ---
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
                    let nonce = Nonce::from_slice(&buffer[..12]);
                    let ciphertext = &buffer[12..size];

                    if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
                        if decrypted == HEARTBEAT_MSG {
                            let _ = app_handle.emit("evento-ping", ());
                        } else {
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

// --- COMANDOS EXPORTADOS ---

#[tauri::command]
fn iniciar_vpn(puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    
    if let Ok(mut lista) = PEERS_GLOBAL.lock() { lista.clear(); }

    let key_bytes = match general_purpose::STANDARD.decode(&clave_b64) {
        Ok(k) => k, Err(_) => return "Clave inválida".to_string(),
    };
    if key_bytes.len() != 32 { return "Longitud incorrecta".to_string(); }
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

    // Configurar IP
    let _ = Command::new("netsh").args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK])
        .creation_flags(CREATE_NO_WINDOW).output();

    // OPTIMIZACIÓN AUTOMÁTICA (NUEVO) 🚀
    // Configuramos Firewall y Prioridad de adaptador
    optimizar_windows(&puerto_local);

    let socket_local = match UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)) {
        Ok(s) => s, Err(e) => return format!("Puerto ocupado: {}", e),
    };

    let session_arc = Arc::new(session);

    // Hilos
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    
    let socket_out = socket_local.try_clone().unwrap();
    let cipher_out = cipher.clone();
    let app_out = app_handle.clone();
    let session_out = session_arc.clone();
    
    thread::spawn(move || {
        loop {
            match session_out.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    if bytes.len() > 0 {
                        if let Ok(lista) = PEERS_GLOBAL.lock() {
                            for ip in lista.iter() {
                                enviar_paquete_seguro(&socket_out, ip, bytes, &cipher_out);
                            }
                            if !lista.is_empty() { let _ = app_out.emit("trafico-salida", bytes.len()); }
                        }
                    }
                },
                Err(_) => break, 
            }
        }
    });

    let socket_latido = socket_local;
    let cipher_latido = cipher.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if let Ok(lista) = PEERS_GLOBAL.lock() {
                for ip in lista.iter() {
                    enviar_paquete_seguro(&socket_latido, ip, HEARTBEAT_MSG, &cipher_latido);
                }
            }
        }
    });

    format!("VPN OPTIMIZADA Y ACTIVA")
}

#[tauri::command]
fn agregar_peer(ip_destino: String) -> String {
    if let Ok(mut lista) = PEERS_GLOBAL.lock() {
        if !lista.contains(&ip_destino) {
            lista.push(ip_destino.clone());
            return format!("OK");
        }
    }
    "Existente".to_string()
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
        .invoke_handler(tauri::generate_handler![iniciar_vpn, agregar_peer, generar_clave_segura])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
