use std::net::{UdpSocket, TcpListener, TcpStream, SocketAddr, SocketAddrV4, Ipv4Addr}; 
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::Emitter;
use std::os::windows::process::CommandExt;
use std::collections::HashMap; 
use std::fs::File; 
use std::io::{Read, Write}; 
use std::path::{Path, PathBuf};

// SEGURIDAD AVANZADA
use x25519_dalek::{PublicKey, StaticSecret}; // Quitamos EphemeralSecret
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 
use lz4_flex::{compress_prepend_size, decompress_size_prepended}; 
use igd_next::search_gateway;
use igd_next::PortMappingProtocol;

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; 
const MAGIC_HEADER: &[u8; 8] = b"MIMIC_V1"; 
const CREATE_NO_WINDOW: u32 = 0x08000000;
const FILE_PORT: u16 = 4444; 

static ROUTING_TABLE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

// --- 1. GENERAR LLAVES (CORREGIDO) ---
#[tauri::command]
fn generar_identidad() -> (String, String) {
    // 1. Generamos 32 bytes aleatorios
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);

    // 2. Creamos la llave Estática directamente
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    
    (
        general_purpose::STANDARD.encode(secret.to_bytes()), // Privada
        general_purpose::STANDARD.encode(public.to_bytes())  // Pública
    )
}

// --- 2. CALCULAR SECRETO COMPARTIDO ---
#[tauri::command]
fn calcular_secreto(mi_privada: String, su_publica: String) -> String {
    let priv_bytes = general_purpose::STANDARD.decode(mi_privada).unwrap_or(vec![0; 32]);
    let pub_bytes = general_purpose::STANDARD.decode(su_publica).unwrap_or(vec![0; 32]);

    if priv_bytes.len() != 32 || pub_bytes.len() != 32 { return "ERROR".to_string(); }

    let mis_secretos = StaticSecret::from(match <[u8; 32]>::try_from(priv_bytes.as_slice()) { Ok(b) => b, Err(_) => return "ERROR".to_string() });
    let sus_publicos = PublicKey::from(match <[u8; 32]>::try_from(pub_bytes.as_slice()) { Ok(b) => b, Err(_) => return "ERROR".to_string() });

    let shared_secret = mis_secretos.diffie_hellman(&sus_publicos);
    general_purpose::STANDARD.encode(shared_secret.as_bytes())
}

fn inicializar_tabla() { let mut t = ROUTING_TABLE.lock().unwrap(); *t = Some(HashMap::new()); }

fn optimizar_windows(p: &str) { 
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", &format!("name=\"MimicHub-UDP-{}\"", p), "dir=in", "action=allow", "protocol=UDP", &format!("localport={}", p)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", "name=\"MimicHub-Files\"", "dir=in", "action=allow", "protocol=TCP", &format!("localport={}", FILE_PORT)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("powershell").args(&["-Command", &format!("Get-NetAdapter -Name '{}' | Set-NetIPInterface -InterfaceMetric 1", NOMBRE_ADAPTADOR)]).creation_flags(CREATE_NO_WINDOW).output();
}

fn enviar_paquete_turbo(socket: &UdpSocket, destino: &str, datos: &[u8], cipher: &ChaCha20Poly1305) {
    let compressed_data = compress_prepend_size(datos);
    let mut nonce_bytes = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce_bytes); let nonce = Nonce::from_slice(&nonce_bytes);
    if let Ok(encrypted_msg) = cipher.encrypt(nonce, compressed_data.as_ref()) {
        let mut final_packet = nonce_bytes.to_vec(); final_packet.extend_from_slice(&encrypted_msg); let _ = socket.send_to(&final_packet, destino);
    }
}

fn obtener_ruta_unica(ruta: PathBuf) -> PathBuf {
    if !ruta.exists() { return ruta; }
    let stem = ruta.file_stem().unwrap().to_string_lossy().to_string();
    let ext = ruta.extension().unwrap_or_default().to_string_lossy().to_string();
    let parent = ruta.parent().unwrap().to_path_buf();
    let mut i = 1;
    loop {
        let name = if ext.is_empty() { format!("{} ({})", stem, i) } else { format!("{} ({}).{}", stem, i, ext) };
        let new_path = parent.join(name); if !new_path.exists() { return new_path; } i += 1;
    }
}

fn iniciar_receptor_archivos<R: tauri::Runtime>(app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{}", FILE_PORT)) {
            for stream in listener.incoming() {
                if let Ok(mut socket) = stream {
                    let handle = app_handle.clone();
                    thread::spawn(move || {
                        let mut header_buf = [0u8; 8];
                        if socket.read_exact(&mut header_buf).is_err() || &header_buf != MAGIC_HEADER { return; }
                        let mut name_len_buf = [0u8; 1];
                        if socket.read_exact(&mut name_len_buf).is_ok() {
                            let name_len = name_len_buf[0] as usize; let mut name_buf = vec![0u8; name_len];
                            if socket.read_exact(&mut name_buf).is_ok() {
                                if let Ok(raw_filename) = String::from_utf8(name_buf) {
                                    if let Some(mut download_path) = dirs::download_dir() {
                                        let safe_name = Path::new(&raw_filename).file_name().unwrap_or_default();
                                        download_path.push(safe_name);
                                        let final_path = obtener_ruta_unica(download_path);
                                        let display_name = final_path.file_name().unwrap().to_string_lossy().to_string();
                                        if let Ok(mut file) = File::create(final_path) {
                                            let mut buffer = [0u8; 8192]; let mut received_bytes = 0;
                                            while let Ok(n) = socket.read(&mut buffer) {
                                                if n == 0 { break; } let _ = file.write_all(&buffer[..n]); received_bytes += n;
                                            }
                                            let _ = handle.emit("archivo-recibido", format!("{} ({:.2} MB)", display_name, received_bytes as f64 / 1024.0 / 1024.0));
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });
}

fn iniciar_hilo_entrada<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                if size > 12 {
                    let nonce = Nonce::from_slice(&buffer[..12]); let ciphertext = &buffer[12..size];
                    if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
                        if let Ok(original) = decompress_size_prepended(&decrypted) {
                            if original == HEARTBEAT_MSG { let _ = app_handle.emit("evento-ping", ()); } 
                            else {
                                if let Ok(mut packet) = session.allocate_send_packet(original.len() as u16) {
                                    packet.bytes_mut().copy_from_slice(&original); session.send_packet(packet);
                                    let _ = app_handle.emit("stats-entrada", (size, original.len()));
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

fn obtener_ip_local() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?; socket.connect("8.8.8.8:80").ok()?; 
    if let Ok(SocketAddr::V4(addr)) = socket.local_addr() { return Some(*addr.ip()); } None
}

#[tauri::command]
fn enviar_archivo(ip_destino: String) -> String {
    let file = rfd::FileDialog::new().set_title("Selecciona archivo").pick_file();
    if let Some(path) = file {
        let path_clone = path.clone(); let ip_target = ip_destino.clone();
        thread::spawn(move || {
            if let Ok(mut file) = File::open(&path_clone) {
                if let Ok(mut socket) = TcpStream::connect(format!("{}:{}", ip_target, FILE_PORT)) {
                    let _ = socket.write_all(MAGIC_HEADER);
                    if let Some(filename) = path_clone.file_name() {
                        if let Some(name_str) = filename.to_str() {
                            let name_bytes = name_str.as_bytes();
                            if name_bytes.len() < 255 {
                                let _ = socket.write_all(&[name_bytes.len() as u8]); let _ = socket.write_all(name_bytes); 
                                let mut buffer = [0u8; 8192];
                                while let Ok(n) = file.read(&mut buffer) { if n == 0 { break; } let _ = socket.write_all(&buffer[..n]); }
                            }
                        }
                    }
                }
            }
        });
        return "Enviando...".to_string();
    } "Cancelado".to_string()
}

#[tauri::command]
fn intentar_upnp(puerto_interno: u16) -> String {
    let local_ip = match obtener_ip_local() { Some(ip) => ip, None => return "Error IP".to_string() };
    match search_gateway(Default::default()) {
        Ok(gateway) => {
            let local_socket = SocketAddrV4::new(local_ip, puerto_interno);
            match gateway.add_port(PortMappingProtocol::UDP, puerto_interno, SocketAddr::V4(local_socket), 0, "MimicHub-UDP") { Ok(_) => format!("ÉXITO UPnP"), Err(e) => format!("FALLO UPnP: {}", e) }
        }, Err(_) => "Router no responde".to_string()
    }
}

#[tauri::command]
fn agregar_peer(ip_destino: String, ip_virtual: String) -> String {
    if let Ok(mut guard) = ROUTING_TABLE.lock() { if let Some(table) = guard.as_mut() { table.insert(ip_virtual, ip_destino); return "OK".to_string(); } } "Error".to_string()
}

#[tauri::command]
fn generar_clave_segura() -> String {
    let mut key = [0u8; 32]; rand::thread_rng().fill_bytes(&mut key); general_purpose::STANDARD.encode(key)
}

#[tauri::command]
fn iniciar_vpn(puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    inicializar_tabla(); 
    let key_bytes = match general_purpose::STANDARD.decode(&clave_b64) { Ok(k) => k, Err(_) => return "Clave mal".to_string() };
    if key_bytes.len() != 32 { return "Longitud mal".to_string(); }
    let key = Key::from_slice(&key_bytes); let cipher = Arc::new(ChaCha20Poly1305::new(key));
    let wintun = unsafe { wintun::load_from_path("wintun.dll") }.unwrap();
    let adapter = wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None).unwrap();
    let session = adapter.start_session(0x400000).unwrap();
    let _ = Command::new("netsh").args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK]).creation_flags(CREATE_NO_WINDOW).output();
    optimizar_windows(&puerto_local);
    iniciar_receptor_archivos(app_handle.clone());
    let socket_local = UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)).unwrap();
    let session_arc = Arc::new(session);
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    let socket_out = socket_local.try_clone().unwrap(); let cipher_out = cipher.clone(); let app_out = app_handle.clone(); let session_out = session_arc.clone();
    thread::spawn(move || {
        loop {
            match session_out.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    if bytes.len() >= 20 { 
                        let dest_ip = format!("{}.{}.{}.{}", bytes[16], bytes[17], bytes[18], bytes[19]);
                        let is_broadcast = dest_ip == "255.255.255.255" || dest_ip.ends_with(".255");
                        if let Ok(guard) = ROUTING_TABLE.lock() {
                            if let Some(table) = guard.as_ref() {
                                if is_broadcast { for t in table.values() { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } } 
                                else { if let Some(t) = table.get(&dest_ip) { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } else { for t in table.values() { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } } }
                                if !table.is_empty() { let _ = app_out.emit("stats-salida", bytes.len()); }
                            }
                        }
                    }
                }, Err(_) => break, 
            }
        }
    });
    let socket_latido = socket_local; let cipher_latido = cipher.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if let Ok(guard) = ROUTING_TABLE.lock() { if let Some(table) = guard.as_ref() { for t in table.values() { enviar_paquete_turbo(&socket_latido, t, HEARTBEAT_MSG, &cipher_latido); } } }
        }
    });
    "VPN E2EE ACTIVA".to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![iniciar_vpn, agregar_peer, generar_identidad, calcular_secreto, intentar_upnp, enviar_archivo, generar_clave_segura])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
