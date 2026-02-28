use std::net::{UdpSocket, TcpListener, TcpStream, SocketAddr, SocketAddrV4, Ipv4Addr}; 
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::Emitter;
use std::os::windows::process::CommandExt;
use std::collections::HashMap; 
use std::fs::File; 
use std::io::{Read, Write, Cursor}; 
use std::path::{Path, PathBuf};
use byteorder::{BigEndian, ReadBytesExt}; 

// SEGURIDAD & UTILIDADES
use x25519_dalek::{PublicKey, StaticSecret}; 
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 
use lz4_flex::{compress_prepend_size, decompress_size_prepended}; 
use igd_next::search_gateway;
use igd_next::PortMappingProtocol;
use sysinfo::System; // <--- CORREGIDO: Solo importamos System

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; 
const HOLE_PUNCH_MSG: &[u8] = b"__MIMIC_PUNCH__";
const MAGIC_HEADER: &[u8; 8] = b"MIMIC_V1"; 
const CREATE_NO_WINDOW: u32 = 0x08000000;
const FILE_PORT: u16 = 4444; 
const STUN_SERVER: &str = "stun.l.google.com:19302";

static ROUTING_TABLE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
static GLOBAL_SOCKET: Mutex<Option<UdpSocket>> = Mutex::new(None);

// --- 1. AUTO-DETECCION DE JUEGOS (VERSIÓN CORREGIDA 0.30+) ---
#[tauri::command]
fn detectar_juego() -> String {
    let mut s = System::new_all();
    s.refresh_all(); // Actualiza lista de procesos

    let juegos = [
        ("javaw.exe", "Minecraft Java"),
        ("Minecraft.Windows.exe", "Minecraft Bedrock"),
        ("haloce.exe", "Halo CE"),
        ("Terraria.exe", "Terraria"),
        ("valheim.exe", "Valheim"),
        ("Among Us.exe", "Among Us"),
        ("Stardew Valley.exe", "Stardew Valley"),
        ("left4dead2.exe", "Left 4 Dead 2"),
        ("csgo.exe", "CS:GO"),
        ("hl2.exe", "Half-Life 2 / GMod"),
        ("Factorio.exe", "Factorio"),
        ("ProjectZomboid64.exe", "Project Zomboid")
    ];

    // Iteramos sobre todos los procesos activos
    for process in s.processes().values() {
        let p_name = process.name().to_lowercase();
        
        for (exe, nombre) in juegos.iter() {
            let exe_limpio = exe.trim_end_matches(".exe").to_lowercase();
            if p_name.contains(&exe_limpio) {
                return nombre.to_string();
            }
        }
    }
    "".to_string()
}

// --- FUNCIONES STUN ---
fn parse_stun_response(response: &[u8]) -> Option<(String, u16)> {
    if response.len() < 20 { return None; }
    if response[0] != 0x01 || response[1] != 0x01 { return None; }
    let mut cursor = Cursor::new(&response[20..]); 
    while let Ok(attr_type) = cursor.read_u16::<BigEndian>() {
        let attr_len = cursor.read_u16::<BigEndian>().unwrap_or(0);
        if attr_type == 0x0020 {
            let _family = cursor.read_u8().unwrap_or(0); 
            let _port = cursor.read_u8().unwrap_or(0); 
            let xor_port = cursor.read_u16::<BigEndian>().unwrap_or(0);
            let xor_ip = cursor.read_u32::<BigEndian>().unwrap_or(0);
            let port = xor_port ^ 0x2112;
            let ip_int = xor_ip ^ 0x2112A442;
            let ip = Ipv4Addr::from(ip_int);
            return Some((ip.to_string(), port));
        }
        if cursor.position() + attr_len as u64 > response.len() as u64 { break; }
        cursor.set_position(cursor.position() + attr_len as u64);
    }
    None
}

fn realizar_consulta_stun(socket: &UdpSocket) -> Option<(String, u16)> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x00; packet[1] = 0x01; 
    packet[2] = 0x00; packet[3] = 0x00; 
    packet[4] = 0x21; packet[5] = 0x12; packet[6] = 0xA4; packet[7] = 0x42; 
    rand::thread_rng().fill_bytes(&mut packet[8..20]);

    if socket.send_to(&packet, STUN_SERVER).is_ok() {
        let mut buf = [0u8; 1024];
        socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
        if let Ok((amt, _src)) = socket.recv_from(&mut buf) {
            socket.set_read_timeout(None).ok();
            return parse_stun_response(&buf[..amt]);
        }
    }
    socket.set_read_timeout(None).ok();
    None
}

// --- COMANDOS EXISTENTES ---
#[tauri::command]
fn generar_identidad() -> (String, String) {
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    (general_purpose::STANDARD.encode(secret.to_bytes()), general_purpose::STANDARD.encode(public.to_bytes()))
}

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

// --- ARCHIVOS ---
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

// --- VPN ENGINE CON QoS y SERVICE DISCOVERY ---
fn iniciar_hilo_entrada<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, _)) = socket.recv_from(&mut buffer) {
                if size == HOLE_PUNCH_MSG.len() && &buffer[..size] == HOLE_PUNCH_MSG { continue; }
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

// --- COMANDOS EXPORTADOS ---
#[tauri::command]
fn obtener_ip_local_cmd() -> String { match obtener_ip_local() { Some(ip) => ip.to_string(), None => "127.0.0.1".to_string() } }

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
    if let Ok(mut guard) = ROUTING_TABLE.lock() { 
        if let Some(table) = guard.as_mut() { 
            table.insert(ip_virtual, ip_destino.clone()); 
            if let Ok(socket_guard) = GLOBAL_SOCKET.lock() {
                if let Some(socket) = socket_guard.as_ref() {
                    let target = ip_destino.clone();
                    let s_clone = socket.try_clone().unwrap();
                    thread::spawn(move || {
                        for _ in 0..5 { let _ = s_clone.send_to(HOLE_PUNCH_MSG, &target); thread::sleep(Duration::from_millis(100)); }
                    });
                }
            }
            return "OK".to_string(); 
        } 
    } "Error".to_string()
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
    
    // STUN CALL
    if let Some((public_ip, public_port)) = realizar_consulta_stun(&socket_local) {
        let _ = app_handle.emit("stun-result", (public_ip, public_port));
    }

    if let Ok(mut s) = GLOBAL_SOCKET.lock() { *s = Some(socket_local.try_clone().unwrap()); }

    let session_arc = Arc::new(session);
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    let socket_out = socket_local.try_clone().unwrap(); let cipher_out = cipher.clone(); let app_out = app_handle.clone(); let session_out = session_arc.clone();
    
    thread::spawn(move || {
        let mut last_tcp_packet = Instant::now();
        loop {
            match session_out.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    
                    // QoS System
                    if bytes.len() > 20 {
                        let protocol = bytes[9];
                        if protocol == 6 { 
                            if last_tcp_packet.elapsed().as_micros() < 500 { thread::sleep(Duration::from_micros(200)); }
                            last_tcp_packet = Instant::now();
                        }
                    }

                    // Service Discovery Broadcast/Multicast
                    if bytes.len() >= 20 { 
                        let dest_ip = format!("{}.{}.{}.{}", bytes[16], bytes[17], bytes[18], bytes[19]);
                        let is_broadcast = dest_ip == "255.255.255.255" || dest_ip.ends_with(".255");
                        let first_byte = bytes[16];
                        let is_multicast = first_byte >= 224 && first_byte <= 239;

                        if let Ok(guard) = ROUTING_TABLE.lock() {
                            if let Some(table) = guard.as_ref() {
                                if is_broadcast || is_multicast { 
                                    for t in table.values() { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } 
                                } else { 
                                    if let Some(t) = table.get(&dest_ip) { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } 
                                    else { for t in table.values() { enviar_paquete_turbo(&socket_out, t, bytes, &cipher_out); } } 
                                }
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
    "VPN COMPLETA: QoS + STUN + DETECCIÓN JUEGOS".to_string()
}

// --- SYSTEM TRAY ---
use tauri::{menu::{Menu, MenuItem}, tray::{MouseButton, TrayIconBuilder, TrayIconEvent}, Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            iniciar_vpn, agregar_peer, generar_identidad, calcular_secreto, 
            intentar_upnp, enviar_archivo, generar_clave_segura, obtener_ip_local_cmd,
            detectar_juego
        ])
        .setup(|app| {
            let quit_i = MenuItem::with_id(app, "quit", "Salir de Mimic Hub", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Mostrar Ventana", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;
            let _tray = TrayIconBuilder::with_id("tray").icon(app.default_window_icon().unwrap().clone()).menu(&menu).on_menu_event(|app, event| { match event.id.as_ref() { "quit" => app.exit(0), "show" => if let Some(window) = app.get_webview_window("main") { let _ = window.show(); let _ = window.set_focus(); }, _ => {} } }).on_tray_icon_event(|tray, event| { if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event { let app = tray.app_handle(); if let Some(window) = app.get_webview_window("main") { let _ = window.show(); let _ = window.set_focus(); } } }).build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| { if let WindowEvent::CloseRequested { api, .. } = event { window.hide().unwrap(); api.prevent_close(); } })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
