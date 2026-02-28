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
use sysinfo::System;

// DISCORD RPC
use discord_rich_presence::{activity, DiscordIpc, DiscordIpcClient};

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";
const HEARTBEAT_MSG: &[u8] = b"__MIMIC_PING__"; 
const HOLE_PUNCH_MSG: &[u8] = b"__MIMIC_PUNCH__";
const MAGIC_HEADER: &[u8; 8] = b"MIMIC_V1"; 
const CREATE_NO_WINDOW: u32 = 0x08000000;
const FILE_PORT: u16 = 4444; 
const STUN_SERVER: &str = "stun.l.google.com:19302";
const DISCORD_CLIENT_ID: &str = "1219918880000000000"; 

static ROUTING_TABLE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
static GLOBAL_SOCKET: Mutex<Option<UdpSocket>> = Mutex::new(None);
static DISCORD_CLIENT: Mutex<Option<DiscordIpcClient>> = Mutex::new(None);

// --- 0. DISCORD ---
fn conectar_discord() {
    let mut guard = DISCORD_CLIENT.lock().unwrap();
    if guard.is_none() {
        if let Ok(mut client) = DiscordIpcClient::new(DISCORD_CLIENT_ID) {
            if client.connect().is_ok() {
                let _ = client.set_activity(activity::Activity::new().state("En el Menú").details("Esperando conexión...").assets(activity::Assets::new().large_image("mimic_logo").large_text("Mimic Hub VPN")));
                *guard = Some(client);
            }
        }
    }
}
fn actualizar_discord(estado: &str, detalles: &str) {
    conectar_discord(); 
    if let Ok(mut guard) = DISCORD_CLIENT.lock() {
        if let Some(client) = guard.as_mut() {
            let _ = client.set_activity(activity::Activity::new().state(estado).details(detalles).assets(activity::Assets::new().large_image("mimic_logo").large_text("Mimic Hub Secure")));
        }
    }
}

// --- 1. AUTO-DETECCION ---
#[tauri::command]
fn detectar_juego() -> String {
    let mut s = System::new_all();
    s.refresh_all(); 
    let juegos = [("javaw.exe", "Minecraft Java"), ("Minecraft.Windows.exe", "Minecraft Bedrock"), ("haloce.exe", "Halo CE"), ("Terraria.exe", "Terraria"), ("valheim.exe", "Valheim"), ("Among Us.exe", "Among Us"), ("Stardew Valley.exe", "Stardew Valley"), ("left4dead2.exe", "Left 4 Dead 2"), ("csgo.exe", "CS:GO"), ("hl2.exe", "Half-Life 2"), ("Factorio.exe", "Factorio"), ("ProjectZomboid64.exe", "Project Zomboid"), ("Content Warning.exe", "Content Warning"), ("Lethal Company.exe", "Lethal Company")];
    for process in s.processes().values() {
        let p_name = process.name().to_lowercase();
        for (exe, nombre) in juegos.iter() {
            if p_name.contains(&exe.trim_end_matches(".exe").to_lowercase()) {
                actualizar_discord("Jugando en LAN", nombre);
                return nombre.to_string();
            }
        }
    }
    if let Ok(guard) = ROUTING_TABLE.lock() { if let Some(table) = guard.as_ref() { if !table.is_empty() { actualizar_discord("Conectado", "En Sala de Espera"); } else { actualizar_discord("Inactivo", "Explorando Mimic Hub"); } } }
    "".to_string()
}

// --- REPARADOR DE PRIORIDAD (IMPORTANTE PARA QUE LOS JUEGOS CONECTEN) ---
#[tauri::command]
fn forzar_prioridad() -> String {
    let _ = Command::new("powershell").args(&["-Command", &format!("Get-NetAdapter -Name '{}' | Set-NetIPInterface -InterfaceMetric 1", NOMBRE_ADAPTADOR)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("powershell").args(&["-Command", &format!("Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private", NOMBRE_ADAPTADOR)]).creation_flags(CREATE_NO_WINDOW).output();
    "Prioridad y Firewall Ajustados 🚑".to_string()
}

// --- FUNCIONES STUN ---
fn parse_stun_response(response: &[u8]) -> Option<(String, u16)> {
    if response.len() < 20 { return None; }
    if response[0] != 0x01 || response[1] != 0x01 { return None; }
    let mut cursor = Cursor::new(&response[20..]); 
    while let Ok(attr_type) = cursor.read_u16::<BigEndian>() {
        let attr_len = cursor.read_u16::<BigEndian>().unwrap_or(0);
        if attr_type == 0x0020 {
            let _ = cursor.read_u8(); let _ = cursor.read_u8(); 
            let xor_port = cursor.read_u16::<BigEndian>().unwrap_or(0);
            let xor_ip = cursor.read_u32::<BigEndian>().unwrap_or(0);
            return Some((Ipv4Addr::from(xor_ip ^ 0x2112A442).to_string(), xor_port ^ 0x2112));
        }
        if cursor.position() + attr_len as u64 > response.len() as u64 { break; }
        cursor.set_position(cursor.position() + attr_len as u64);
    }
    None
}
fn realizar_consulta_stun(socket: &UdpSocket) -> Option<(String, u16)> {
    let mut packet = vec![0u8; 20]; packet[0]=0; packet[1]=1; packet[4]=0x21; packet[5]=0x12; packet[6]=0xA4; packet[7]=0x42; rand::thread_rng().fill_bytes(&mut packet[8..20]);
    if socket.send_to(&packet, STUN_SERVER).is_ok() {
        let mut buf = [0u8; 1024]; socket.set_read_timeout(Some(Duration::from_millis(500))).ok();
        if let Ok((amt, _)) = socket.recv_from(&mut buf) { socket.set_read_timeout(None).ok(); return parse_stun_response(&buf[..amt]); }
    }
    socket.set_read_timeout(None).ok(); None
}

// --- COMANDOS BASICOS ---
#[tauri::command]
fn generar_identidad() -> (String, String) { let mut s=[0u8;32]; rand::thread_rng().fill_bytes(&mut s); let sec=StaticSecret::from(s); (general_purpose::STANDARD.encode(sec.to_bytes()), general_purpose::STANDARD.encode(PublicKey::from(&sec).to_bytes())) }
#[tauri::command]
fn calcular_secreto(mi_privada: String, su_publica: String) -> String {
    let p1 = general_purpose::STANDARD.decode(mi_privada).unwrap_or(vec![0;32]); let p2 = general_purpose::STANDARD.decode(su_publica).unwrap_or(vec![0;32]);
    if p1.len()!=32 || p2.len()!=32 { return "ERROR".to_string(); }
    general_purpose::STANDARD.encode(StaticSecret::from(<[u8;32]>::try_from(p1.as_slice()).unwrap()).diffie_hellman(&PublicKey::from(<[u8;32]>::try_from(p2.as_slice()).unwrap())).as_bytes())
}
fn inicializar_tabla() { let mut t = ROUTING_TABLE.lock().unwrap(); *t = Some(HashMap::new()); }
fn optimizar_windows(p: &str) { 
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", &format!("name=\"MimicHub-UDP-{}\"", p), "dir=in", "action=allow", "protocol=UDP", &format!("localport={}", p)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("netsh").args(&["advfirewall", "firewall", "add", "rule", "name=\"MimicHub-Files\"", "dir=in", "action=allow", "protocol=TCP", &format!("localport={}", FILE_PORT)]).creation_flags(CREATE_NO_WINDOW).output();
    let _ = Command::new("powershell").args(&["-Command", &format!("Get-NetAdapter -Name '{}' | Set-NetIPInterface -InterfaceMetric 1", NOMBRE_ADAPTADOR)]).creation_flags(CREATE_NO_WINDOW).output();
}
fn enviar_paquete_turbo(socket: &UdpSocket, destino: &str, datos: &[u8], cipher: &ChaCha20Poly1305) {
    let mut n = [0u8; 12]; rand::thread_rng().fill_bytes(&mut n);
    if let Ok(e) = cipher.encrypt(Nonce::from_slice(&n), compress_prepend_size(datos).as_ref()) { let mut f = n.to_vec(); f.extend_from_slice(&e); let _ = socket.send_to(&f, destino); }
}
fn obtener_ruta_unica(ruta: PathBuf) -> PathBuf {
    if !ruta.exists() { return ruta; }
    let s=ruta.file_stem().unwrap().to_string_lossy(); let e=ruta.extension().unwrap_or_default().to_string_lossy(); let p=ruta.parent().unwrap(); let mut i=1;
    loop { let n=if e.is_empty(){format!("{} ({})",s,i)}else{format!("{} ({}).{}",s,i,e)}; let np=p.join(n); if !np.exists(){return np;} i+=1; }
}
fn iniciar_receptor_archivos<R: tauri::Runtime>(app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        if let Ok(l) = TcpListener::bind(format!("0.0.0.0:{}", FILE_PORT)) {
            for s in l.incoming() { if let Ok(mut sock) = s { let h=app_handle.clone(); thread::spawn(move || {
                let mut head=[0u8;8]; if sock.read_exact(&mut head).is_err() || &head!=MAGIC_HEADER {return;}
                let mut nl=[0u8;1]; if sock.read_exact(&mut nl).is_ok() {
                    let mut nb=vec![0u8;nl[0] as usize]; if sock.read_exact(&mut nb).is_ok() {
                        if let Ok(rn) = String::from_utf8(nb) {
                            if let Some(mut dp) = dirs::download_dir() {
                                dp.push(Path::new(&rn).file_name().unwrap_or_default()); let fp=obtener_ruta_unica(dp); let dn=fp.file_name().unwrap().to_string_lossy().to_string();
                                if let Ok(mut f) = File::create(fp) {
                                    let mut b=[0u8;8192]; let mut rb=0; while let Ok(n)=sock.read(&mut b) { if n==0{break;} let _=f.write_all(&b[..n]); rb+=n; }
                                    let _=h.emit("archivo-recibido", format!("{} ({:.2} MB)", dn, rb as f64/1048576.0));
                                }
                            }
                        }
                    }
                }
            });}}
        }
    });
}
fn iniciar_hilo_entrada<R: tauri::Runtime>(session: Arc<wintun::Session>, socket: UdpSocket, cipher: Arc<ChaCha20Poly1305>, app_handle: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut b = [0; 65535]; 
        loop {
            if let Ok((s, _)) = socket.recv_from(&mut b) {
                if s == HOLE_PUNCH_MSG.len() && &b[..s] == HOLE_PUNCH_MSG { continue; }
                if s > 12 {
                    if let Ok(d) = cipher.decrypt(Nonce::from_slice(&b[..12]), &b[12..s]) {
                        if let Ok(o) = decompress_size_prepended(&d) {
                            if o == HEARTBEAT_MSG { let _ = app_handle.emit("evento-ping", ()); } 
                            else if let Ok(mut p) = session.allocate_send_packet(o.len() as u16) { p.bytes_mut().copy_from_slice(&o); session.send_packet(p); let _ = app_handle.emit("stats-entrada", (s, o.len())); }
                        }
                    }
                }
            }
        }
    });
}
fn obtener_ip_local() -> Option<Ipv4Addr> { let s=UdpSocket::bind("0.0.0.0:0").ok()?; s.connect("8.8.8.8:80").ok()?; if let Ok(SocketAddr::V4(a))=s.local_addr(){return Some(*a.ip());} None }
#[tauri::command] fn obtener_ip_local_cmd() -> String { match obtener_ip_local() { Some(i)=>i.to_string(), None=>"127.0.0.1".to_string() } }
#[tauri::command] fn enviar_archivo(ip_destino: String) -> String {
    let f = rfd::FileDialog::new().set_title("Selecciona archivo").pick_file();
    if let Some(p) = f { let pc=p.clone(); let ipt=ip_destino.clone(); thread::spawn(move || {
        if let Ok(mut fi) = File::open(&pc) { if let Ok(mut s) = TcpStream::connect(format!("{}:{}", ipt, FILE_PORT)) {
            let _=s.write_all(MAGIC_HEADER); if let Some(n)=pc.file_name() { if let Some(ns)=n.to_str() { let nb=ns.as_bytes(); if nb.len()<255 {
                let _=s.write_all(&[nb.len() as u8]); let _=s.write_all(nb); let mut b=[0u8;8192]; while let Ok(n)=fi.read(&mut b) { if n==0{break;} let _=s.write_all(&b[..n]); }
            }}}}}}); "Enviando...".to_string() } else { "Cancelado".to_string() }
}
#[tauri::command] fn intentar_upnp(puerto_interno: u16) -> String {
    let l = match obtener_ip_local() { Some(i)=>i, None=>return "Error IP".to_string() };
    match search_gateway(Default::default()) { Ok(g) => match g.add_port(PortMappingProtocol::UDP, puerto_interno, SocketAddr::V4(SocketAddrV4::new(l, puerto_interno)), 0, "MimicHub-UDP") { Ok(_)=>"ÉXITO UPnP".to_string(), Err(e)=>format!("FALLO UPnP: {}", e) }, Err(_)=>"Router no responde".to_string() }
}
#[tauri::command] fn agregar_peer(ip_destino: String, ip_virtual: String) -> String {
    if let Ok(mut g) = ROUTING_TABLE.lock() { if let Some(t) = g.as_mut() { t.insert(ip_virtual, ip_destino.clone()); 
        if let Ok(sg)=GLOBAL_SOCKET.lock() { if let Some(s)=sg.as_ref() { let tg=ip_destino.clone(); let sc=s.try_clone().unwrap(); thread::spawn(move || { for _ in 0..5 { let _=sc.send_to(HOLE_PUNCH_MSG, &tg); thread::sleep(Duration::from_millis(100)); } }); }}
        return "OK".to_string(); 
    }} "Error".to_string()
}
#[tauri::command] fn generar_clave_segura() -> String { let mut k=[0u8;32]; rand::thread_rng().fill_bytes(&mut k); general_purpose::STANDARD.encode(k) }

#[tauri::command]
fn iniciar_vpn(puerto_local: String, ip_virtual: String, clave_b64: String, app_handle: tauri::AppHandle) -> String {
    inicializar_tabla(); actualizar_discord("Conectado a Mimic Hub", "Esperando Paquetes...");
    let kb = match general_purpose::STANDARD.decode(&clave_b64) { Ok(k) => k, Err(_) => return "Clave mal".to_string() }; if kb.len()!=32 { return "Longitud mal".to_string(); }
    let k = Key::from_slice(&kb); let c = Arc::new(ChaCha20Poly1305::new(k));
    let w = unsafe { wintun::load_from_path("wintun.dll") }.unwrap(); let a = wintun::Adapter::create(&w, "MimicV2", NOMBRE_ADAPTADOR, None).unwrap(); let s = a.start_session(0x400000).unwrap();
    let _ = Command::new("netsh").args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK]).creation_flags(CREATE_NO_WINDOW).output();
    optimizar_windows(&puerto_local); iniciar_receptor_archivos(app_handle.clone());
    
    let sl = UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)).unwrap();
    if let Some((pip, pport)) = realizar_consulta_stun(&sl) { let _=app_handle.emit("stun-result", (pip, pport)); }
    if let Ok(mut g) = GLOBAL_SOCKET.lock() { *g = Some(sl.try_clone().unwrap()); }

    let sa = Arc::new(s); iniciar_hilo_entrada(sa.clone(), sl.try_clone().unwrap(), c.clone(), app_handle.clone());
    let so = sl.try_clone().unwrap(); let co = c.clone(); let ao = app_handle.clone(); let sso = sa.clone();
    
    thread::spawn(move || { let mut ltp = Instant::now(); loop { match sso.receive_blocking() { Ok(p) => {
        let b = p.bytes(); if b.len()>20 && b[9]==6 { if ltp.elapsed().as_micros()<500 { thread::sleep(Duration::from_micros(200)); } ltp=Instant::now(); }
        if b.len()>=20 { 
            let d = format!("{}.{}.{}.{}", b[16], b[17], b[18], b[19]); let is_b = d=="255.255.255.255" || d.ends_with(".255") || (b[16]>=224 && b[16]<=239);
            if let Ok(g) = ROUTING_TABLE.lock() { if let Some(t) = g.as_ref() {
                if is_b { for tg in t.values() { enviar_paquete_turbo(&so, tg, b, &co); } } else { if let Some(tg) = t.get(&d) { enviar_paquete_turbo(&so, tg, b, &co); } else { for tg in t.values() { enviar_paquete_turbo(&so, tg, b, &co); } } }
                if !t.is_empty() { let _=ao.emit("stats-salida", b.len()); }
            }}
        }
    }, Err(_) => break, } } });
    let sl2 = sl; let cl2 = c.clone(); thread::spawn(move || { loop { thread::sleep(Duration::from_secs(2)); if let Ok(g) = ROUTING_TABLE.lock() { if let Some(t) = g.as_ref() { for tg in t.values() { enviar_paquete_turbo(&sl2, tg, HEARTBEAT_MSG, &cl2); } } } } });
    "VPN COMPLETA".to_string()
}

use tauri::{menu::{Menu, MenuItem}, tray::{MouseButton, TrayIconBuilder, TrayIconEvent}, Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            iniciar_vpn, agregar_peer, generar_identidad, calcular_secreto, 
            intentar_upnp, enviar_archivo, generar_clave_segura, obtener_ip_local_cmd,
            detectar_juego, forzar_prioridad // <--- AQUI ESTA EL COMANDO QUE FALTABA
        ])
        .setup(|app| {
            conectar_discord(); 
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
