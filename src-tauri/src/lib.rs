use std::net::{UdpSocket, TcpListener, TcpStream, SocketAddr, SocketAddrV4, Ipv4Addr}; 
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Emitter, Listener, Manager}; 
use std::os::windows::process::CommandExt;
use std::collections::{HashMap, HashSet}; 
use std::fs::File; 
use std::io::{Read, Write, Cursor}; 
use std::path::{Path, PathBuf};
use byteorder::{BigEndian, ReadBytesExt}; 

use x25519_dalek::{PublicKey, StaticSecret}; 
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; 
use chacha20poly1305::aead::{Aead, KeyInit}; 
use rand::RngCore; 
use base64::{Engine as _, engine::general_purpose}; 
use lz4_flex::{compress_prepend_size, decompress_size_prepended}; 
use igd_next::search_gateway;
use igd_next::PortMappingProtocol;
use sysinfo::System;
use discord_rich_presence::{activity, DiscordIpc, DiscordIpcClient};
use tauri_plugin_deep_link::DeepLinkExt; 

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; 
const RAW_PING: &[u8] = b"PING_ABIERTO"; // SEÑAL DE PRUEBA
const HOLE_PUNCH_MSG: &[u8] = b"__MIMIC_PUNCH__";
const MAGIC_HEADER: &[u8; 8] = b"MIMIC_V1"; 
const CREATE_NO_WINDOW: u32 = 0x08000000;
const FILE_PORT: u16 = 4444; 
const STUN_SERVER: &str = "stun.l.google.com:19302";
const DISCORD_CLIENT_ID: &str = "1219918880000000000"; 

static ROUTING_TABLE: Mutex<Option<HashMap<String, HashSet<String>>>> = Mutex::new(None);
static GLOBAL_SOCKET: Mutex<Option<UdpSocket>> = Mutex::new(None);
static DISCORD_CLIENT: Mutex<Option<DiscordIpcClient>> = Mutex::new(None);
static RELAY_ADDRESS: Mutex<Option<String>> = Mutex::new(None);
lazy_static::lazy_static! { static ref PEER_LAST_SEEN: Mutex<HashMap<String, Instant>> = Mutex::new(HashMap::new()); }

fn es_paquete_seguro(packet: &[u8]) -> bool {
    if packet.len() < 20 { return false; }
    let protocol = packet[9];
    if protocol != 6 && protocol != 17 && protocol != 1 && protocol != 2 { return false; }
    if protocol == 6 || protocol == 17 { 
        if packet.len() < 24 { return false; } 
        let dest_port = ((packet[22] as u16) << 8) | (packet[23] as u16);
        match dest_port { 135 | 137 | 138 | 139 | 445 | 3389 | 5900 | 23 | 21 => return false, _ => {} }
    }
    true
}

// --- ENVÍO HÍBRIDO (SEGURO + ABIERTO) ---
fn enviar_paquete_smart(socket: &UdpSocket, ip_virtual_destino: &str, rutas_destino: &HashSet<String>, datos: &[u8], cipher: &ChaCha20Poly1305) {
    let compressed_data = compress_prepend_size(datos);
    let mut nonce_bytes = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce_bytes); let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 1. Preparar paquete encriptado
    if let Ok(encrypted_msg) = cipher.encrypt(nonce, compressed_data.as_ref()) {
        let mut final_packet = nonce_bytes.to_vec(); 
        final_packet.extend_from_slice(&encrypted_msg);
        
        let relay_target = { let guard = RELAY_ADDRESS.lock().unwrap(); guard.clone() };
        
        // P2P
        for endpoint in rutas_destino { let _ = socket.send_to(&final_packet, endpoint); }

        // RELAY
        if let Some(relay_ip) = relay_target {
            if let Ok(ip_addr) = ip_virtual_destino.parse::<Ipv4Addr>() {
                // Enviar Encriptado
                let mut relay_packet = ip_addr.octets().to_vec(); 
                relay_packet.extend_from_slice(&final_packet);    
                let _ = socket.send_to(&relay_packet, &relay_ip);

                // DIAGNÓSTICO: Enviar también PING ABIERTO a través del Relay
                // Solo si son datos de Heartbeat para no saturar
                if datos == HEARTBEAT_MSG {
                    let mut raw_packet = ip_addr.octets().to_vec();
                    raw_packet.extend_from_slice(RAW_PING);
                    let _ = socket.send_to(&raw_packet, &relay_ip);
                }
            }
        }
    }
}

fn enviar_paquete_turbo(socket: &UdpSocket, destino: &str, datos: &[u8], cipher: &ChaCha20Poly1305) {
    let compressed_data = compress_prepend_size(datos);
    let mut nonce_bytes = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce_bytes); let nonce = Nonce::from_slice(&nonce_bytes);
    if let Ok(encrypted_msg) = cipher.encrypt(nonce, compressed_data.as_ref()) {
        let mut final_packet = nonce_bytes.to_vec(); final_packet.extend_from_slice(&encrypted_msg);
        let _ = socket.send_to(&final_packet, destino);
    }
}

// ... Utilidades Discord y Windows ...
fn conectar_discord() {
    let mut guard = DISCORD_CLIENT.lock().unwrap();
    if guard.is_none() {
        if let Ok(mut client) = DiscordIpcClient::new(DISCORD_CLIENT_ID) {
            if client.connect().is_ok() { let _ = client.set_activity(activity::Activity::new().state("En el Menú").assets(activity::Assets::new().large_image("mimic_logo"))); *guard = Some(client); }
        }
    }
}
fn actualizar_discord(estado: &str, detalles: &str) {
    conectar_discord(); 
    if let Ok(mut guard) = DISCORD_CLIENT.lock() { if let Some(client) = guard.as_mut() { let _ = client.set_activity(activity::Activity::new().state(estado).details(detalles).assets(activity::Assets::new().large_image("mimic_logo"))); } }
}
fn optimizar_windows_nuclear(puerto_udp: &str) { 
    let _ = Command::new("powershell").args(&["-Command", "Add-MpPreference -ExclusionProcess 'mimic-app.exe' -ErrorAction SilentlyContinue"]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("netsh").args(&["interface", "ipv4", "set", "subinterface", NOMBRE_ADAPTADOR, "mtu=1350", "store=persistent"]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("powershell").args(&["-Command", &format!("Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private", NOMBRE_ADAPTADOR)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", "name=\"MimicHub-TOTAL-IN\"", "dir=in", "action=allow", "protocol=UDP", "localport=any", "remoteport=any"]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", "name=\"MimicHub-TOTAL-OUT\"", "dir=out", "action=allow", "protocol=UDP", "localport=any", "remoteport=any"]).creation_flags(CREATE_NO_WINDOW).output();
}
#[tauri::command]
fn forzar_prioridad() -> String { optimizar_windows_nuclear("0"); "🚀 Firewall Abierto".to_string() }
#[tauri::command]
fn detectar_juego() -> String {
    let mut s = System::new_all(); s.refresh_all(); 
    let juegos = [("javaw.exe", "Minecraft Java"), ("Minecraft.Windows.exe", "Minecraft Bedrock"), ("haloce.exe", "Halo CE"), ("Terraria.exe", "Terraria"), ("valheim.exe", "Valheim"), ("Among Us.exe", "Among Us"), ("Stardew Valley.exe", "Stardew Valley"), ("left4dead2.exe", "Left 4 Dead 2"), ("csgo.exe", "CS:GO"), ("hl2.exe", "Half-Life 2"), ("Factorio.exe", "Factorio"), ("ProjectZomboid64.exe", "Project Zomboid"), ("Content Warning.exe", "Content Warning"), ("Lethal Company.exe", "Lethal Company")];
    for process in s.processes().values() {
        let p_name = process.name().to_lowercase();
        for (exe, nombre) in juegos.iter() { if p_name.contains(&exe.trim_end_matches(".exe").to_lowercase()) { actualizar_discord("Jugando en LAN", nombre); return nombre.to_string(); } }
    }
    "".to_string()
}
fn parse_stun_response(response: &[u8]) -> Option<(String, u16)> {
    if response.len() < 20 || response[0] != 0x01 { return None; }
    let mut cursor = Cursor::new(&response[20..]); 
    while let Ok(attr_type) = cursor.read_u16::<BigEndian>() {
        let attr_len = cursor.read_u16::<BigEndian>().unwrap_or(0);
        if attr_type == 0x0020 {
            let _ = cursor.read_u16::<BigEndian>(); // family & port placeholder
            let xor_port = cursor.read_u16::<BigEndian>().unwrap_or(0);
            let xor_ip = cursor.read_u32::<BigEndian>().unwrap_or(0);
            return Some((Ipv4Addr::from(xor_ip ^ 0x2112A442).to_string(), xor_port ^ 0x2112));
        }
        cursor.set_position(cursor.position() + attr_len as u64);
    }
    None
}
fn realizar_consulta_stun(socket: &UdpSocket) -> Option<(String, u16)> {
    let mut packet = vec![0u8; 20]; packet[0] = 0x00; packet[1] = 0x01; packet[4] = 0x21; packet[5] = 0x12; packet[6] = 0xA4; packet[7] = 0x42;
    rand::thread_rng().fill_bytes(&mut packet[8..20]);
    if socket.send_to(&packet, STUN_SERVER).is_ok() {
        let mut buf = [0u8; 1024]; socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
        if let Ok((amt, _)) = socket.recv_from(&mut buf) { socket.set_read_timeout(None).ok(); return parse_stun_response(&buf[..amt]); }
    }
    socket.set_read_timeout(None).ok(); None
}
#[tauri::command]
fn generar_identidad() -> (String, String) {
    let mut s = [0u8; 32]; rand::thread_rng().fill_bytes(&mut s);
    let secret = StaticSecret::from(s); let public = PublicKey::from(&secret);
    (general_purpose::STANDARD.encode(secret.to_bytes()), general_purpose::STANDARD.encode(public.to_bytes()))
}
#[tauri::command]
fn calcular_secreto(mi_privada: String, su_publica: String) -> String {
    let p = general_purpose::STANDARD.decode(mi_privada).unwrap_or(vec![0;32]);
    let u = general_purpose::STANDARD.decode(su_publica).unwrap_or(vec![0;32]);
    if p.len()!=32 || u.len()!=32 { return "ERROR".to_string(); }
    let s = StaticSecret::from(<[u8;32]>::try_from(p.as_slice()).unwrap());
    let k = PublicKey::from(<[u8;32]>::try_from(u.as_slice()).unwrap());
    general_purpose::STANDARD.encode(s.diffie_hellman(&k).as_bytes())
}
fn inicializar_tabla() { let mut t = ROUTING_TABLE.lock().unwrap(); *t = Some(HashMap::new()); }
fn obtener_ruta_unica(ruta: PathBuf) -> PathBuf {
    if !ruta.exists() { return ruta; }
    let stem = ruta.file_stem().unwrap().to_string_lossy(); let ext = ruta.extension().unwrap_or_default().to_string_lossy();
    let mut i = 1; loop { let n = if ext.is_empty() { format!("{} ({})", stem, i) } else { format!("{} ({}).{}", stem, i, ext) }; let np = ruta.parent().unwrap().join(n); if !np.exists() { return np; } i += 1; }
}
fn iniciar_receptor_archivos<R: tauri::Runtime>(app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        if let Ok(l) = TcpListener::bind(format!("0.0.0.0:{}", FILE_PORT)) {
            for s in l.incoming() { if let Ok(mut c) = s {
                let h = app_handle.clone(); thread::spawn(move || {
                    let mut b = [0u8;8]; if c.read_exact(&mut b).is_err() || &b != MAGIC_HEADER { return; }
                    let mut l = [0u8;1]; if c.read_exact(&mut l).is_ok() {
                        let mut n = vec![0u8; l[0] as usize]; if c.read_exact(&mut n).is_ok() {
                            if let Ok(name) = String::from_utf8(n) {
                                if let Some(mut d) = dirs::download_dir() {
                                    d.push(Path::new(&name).file_name().unwrap()); let p = obtener_ruta_unica(d);
                                    if let Ok(mut f) = File::create(&p) {
                                        let mut buf = [0u8;8192]; let mut tot = 0;
                                        while let Ok(n) = c.read(&mut buf) { if n==0 { break; } let _ = f.write_all(&buf[..n]); tot+=n; }
                                        let _ = h.emit("archivo-recibido", format!("{} ({:.2} MB)", p.file_name().unwrap().to_string_lossy(), tot as f64/1048576.0));
                                    }
                                }
                            }
                        }
                    }
                });
            }}
        }
    });
}

// --- RECEPCIÓN HÍBRIDA (LA CLAVE DEL ÉXITO) ---
fn iniciar_hilo_entrada<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            if let Ok((size, src)) = socket.recv_from(&mut buffer) {
                // ACTUALIZAR TIMESTAMP
                { let mut guard = PEER_LAST_SEEN.lock().unwrap(); guard.insert(src.to_string(), Instant::now()); }
                
                // 1. CHEQUEO DE PING ABIERTO (DIAGNÓSTICO)
                // Si esto funciona, el ping en la app se pondrá en ROJO o NÚMEROS, ignorando la encriptación.
                if size == RAW_PING.len() && &buffer[..size] == RAW_PING {
                    let _ = app_handle.emit("evento-ping", "⚠️ MODO INSEGURO");
                    continue; 
                }

                if size > 12 && (size != HOLE_PUNCH_MSG.len() || &buffer[..size] != HOLE_PUNCH_MSG) {
                    let nonce = Nonce::from_slice(&buffer[..12]);
                    if let Ok(dec) = cipher.decrypt(nonce, &buffer[12..size]) {
                        if let Ok(orig) = decompress_size_prepended(&dec) {
                            if !es_paquete_seguro(&orig) { continue; }
                            
                            // 2. CHEQUEO SEGURO
                            if orig == HEARTBEAT_MSG { 
                                let _ = app_handle.emit("evento-ping", "🔒 SEGURO"); 
                            }
                            else if let Ok(mut p) = session.allocate_send_packet(orig.len() as u16) {
                                p.bytes_mut().copy_from_slice(&orig); session.send_packet(p);
                                let _ = app_handle.emit("stats-entrada", (size, orig.len()));
                            }
                        }
                    }
                }
            }
        }
    });
}
fn obtener_ip_local() -> Option<Ipv4Addr> { let s = UdpSocket::bind("0.0.0.0:0").ok()?; s.connect("8.8.8.8:80").ok()?; if let Ok(SocketAddr::V4(a)) = s.local_addr() { Some(*a.ip()) } else { None } }
#[tauri::command]
fn obtener_ip_local_cmd() -> String { obtener_ip_local().map(|i| i.to_string()).unwrap_or("127.0.0.1".to_string()) }
#[tauri::command]
fn enviar_archivo(ip_destino: String) -> String {
    let f = rfd::FileDialog::new().pick_file();
    if let Some(p) = f {
        let pc = p.clone(); let ip = ip_destino.clone();
        thread::spawn(move || {
            if let Ok(mut f) = File::open(&pc) {
                if let Ok(mut s) = TcpStream::connect(format!("{}:{}", ip, FILE_PORT)) {
                    let _ = s.write_all(MAGIC_HEADER);
                    if let Some(n) = pc.file_name().and_then(|n| n.to_str()) {
                        let b = n.as_bytes(); if b.len() < 255 {
                            let _ = s.write_all(&[b.len() as u8]); let _ = s.write_all(b);
                            let mut buf = [0u8;8192]; while let Ok(n) = f.read(&mut buf) { if n==0 { break; } let _ = s.write_all(&buf[..n]); }
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
        Ok(gateway) => match gateway.add_port(PortMappingProtocol::UDP, puerto_interno, SocketAddr::V4(SocketAddrV4::new(local_ip, puerto_interno)), 0, "MimicHub") { Ok(_) => "UPnP OK".to_string(), Err(e) => format!("UPnP Fail: {}", e) },
        Err(_) => "No Router".to_string()
    }
}
#[tauri::command]
fn agregar_peer(ip_destino: String, ip_virtual: String) -> String {
    if let Ok(mut guard) = ROUTING_TABLE.lock() { if let Some(t) = guard.as_mut() { t.entry(ip_virtual).or_insert(HashSet::new()).insert(ip_destino); return "OK".to_string(); } } "Error".to_string()
}
#[tauri::command]
fn generar_clave_segura() -> String { let mut k=[0u8;32]; rand::thread_rng().fill_bytes(&mut k); general_purpose::STANDARD.encode(k) }

#[tauri::command]
fn activar_relay(server_ip: String, mi_ip_virtual: String) -> String {
    if let Ok(mut guard) = RELAY_ADDRESS.lock() { *guard = Some(server_ip.clone()); }
    if let Ok(socket_guard) = GLOBAL_SOCKET.lock() {
        if let Some(socket) = socket_guard.as_ref() {
            if let Ok(s_clone) = socket.try_clone() {
                let target = server_ip.clone();
                if let Ok(ip_addr) = mi_ip_virtual.parse::<Ipv4Addr>() {
                    let mut reg_packet = vec![0xFF]; 
                    reg_packet.extend_from_slice(&ip_addr.octets());
                    thread::spawn(move || { 
                        loop { 
                            let _ = s_clone.send_to(&reg_packet, &target); 
                            thread::sleep(Duration::from_secs(5)); 
                            if RELAY_ADDRESS.lock().unwrap().is_none() { break; } 
                        } 
                    });
                }
            }
        }
    }
    "Conectado a Playit Relay 🚀".to_string()
}

#[tauri::command]
fn iniciar_vpn(puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    inicializar_tabla(); actualizar_discord("Conectado", "Modo Relay Activo");
    let key_bytes = general_purpose::STANDARD.decode(&clave_b64).unwrap();
    let key = Key::from_slice(&key_bytes); let cipher = Arc::new(ChaCha20Poly1305::new(key));
    let wintun = unsafe { wintun::load_from_path("wintun.dll").unwrap() };
    let adapter = wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None).unwrap();
    let session = adapter.start_session(0x400000).unwrap();
    let _ = Command::new("netsh").args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK]).creation_flags(CREATE_NO_WINDOW).output();
    optimizar_windows_nuclear(&puerto_local);
    if let Ok(p) = puerto_local.parse::<u16>() { thread::spawn(move || { let _ = intentar_upnp(p); }); }

    iniciar_receptor_archivos(app_handle.clone());
    let socket_local = UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)).unwrap();
    if let Some((ip, port)) = realizar_consulta_stun(&socket_local) { let _ = app_handle.emit("stun-result", (ip, port)); }
    if let Ok(mut s) = GLOBAL_SOCKET.lock() { *s = Some(socket_local.try_clone().unwrap()); }

    let session_arc = Arc::new(session);
    iniciar_hilo_entrada(session_arc.clone(), socket_local.try_clone().unwrap(), cipher.clone(), app_handle.clone());
    
    let socket_out = socket_local.try_clone().unwrap(); let cipher_out = cipher.clone(); let app_out = app_handle.clone(); let session_out = session_arc.clone();
    
    thread::spawn(move || {
        loop {
            if let Ok(packet) = session_out.receive_blocking() {
                let bytes = packet.bytes();
                if bytes.len() >= 20 {
                    let dest_ip = format!("{}.{}.{}.{}", bytes[16], bytes[17], bytes[18], bytes[19]);
                    let is_broadcast = dest_ip.ends_with(".255") || bytes[16] >= 224;
                    if let Ok(guard) = ROUTING_TABLE.lock() {
                        if let Some(table) = guard.as_ref() {
                            if is_broadcast {
                                for (vip, routes) in table.iter() { 
                                    if *vip != ip_virtual { enviar_paquete_smart(&socket_out, vip, routes, bytes, &cipher_out); } 
                                }
                            } else if let Some(routes) = table.get(&dest_ip) {
                                enviar_paquete_smart(&socket_out, &dest_ip, routes, bytes, &cipher_out);
                            }
                            if !table.is_empty() { let _ = app_out.emit("stats-salida", bytes.len()); }
                        }
                    }
                }
            } else { break; }
        }
    });
    
    let socket_hb = socket_local; let cipher_hb = cipher.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            if let Ok(guard) = ROUTING_TABLE.lock() { if let Some(table) = guard.as_ref() {
                for (vip, routes) in table.iter() { enviar_paquete_smart(&socket_hb, vip, routes, HEARTBEAT_MSG, &cipher_hb); }
            }}
        }
    });
    "VPN Activa".to_string()
}

use tauri::{menu::{Menu, MenuItem}, tray::{MouseButton, TrayIconBuilder, TrayIconEvent}, WindowEvent};
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build()) .plugin(tauri_plugin_opener::init()) .plugin(tauri_plugin_deep_link::init())
        .invoke_handler(tauri::generate_handler![ iniciar_vpn, agregar_peer, generar_identidad, calcular_secreto, intentar_upnp, enviar_archivo, generar_clave_segura, obtener_ip_local_cmd, detectar_juego, forzar_prioridad, activar_relay ])
        .setup(|app| {
            conectar_discord(); let h = app.handle().clone();
            app.listen("deep-link://new-url", move |e| { if let Ok(u) = serde_json::from_str::<Vec<String>>(e.payload()) { if let Some(s) = u.first() { let _ = h.emit("open-url", s); } } });
            let q = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?; let s = MenuItem::with_id(app, "show", "Mostrar", true, None::<&str>)?;
            let m = Menu::with_items(app, &[&s, &q])?;
            let _ = TrayIconBuilder::with_id("tray").icon(app.default_window_icon().unwrap().clone()).menu(&m).on_menu_event(|a,e|{ match e.id.as_ref() { "quit"=>a.exit(0), "show"=>if let Some(w)=a.get_webview_window("main"){let _=w.show();let _=w.set_focus();}, _=>{} } }).build(app)?;
            Ok(())
        })
        .on_window_event(|w,e| { if let WindowEvent::CloseRequested{api,..}=e { w.hide().unwrap(); api.prevent_close(); } })
        .run(tauri::generate_context!()).expect("error");
}
