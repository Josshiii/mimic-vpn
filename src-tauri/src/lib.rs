use std::net::{UdpSocket, SocketAddr}; // Importamos SocketAddr
use std::process::Command;
use std::sync::Arc;
use std::thread;
use tauri::Emitter;
// Importamos la librería para hablar con el Router
use igd_next::search_gateway;
use igd_next::SearchOptions;

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";

// --- FUNCIONES DE TÚNEL ---
fn iniciar_hilo_salida<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket, 
    ip_amigo: String,
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        loop {
            match session.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    if bytes.len() > 0 {
                        match socket.send_to(bytes, &ip_amigo) {
                            Ok(_) => { let _ = app_handle.emit("trafico-salida", bytes.len()); },
                            Err(e) => println!("Error enviando: {}", e),
                        }
                    }
                },
                Err(_) => break,
            }
        }
    });
}

fn iniciar_hilo_entrada<R: tauri::Runtime>(
    session: Arc<wintun::Session>, 
    socket: UdpSocket,
    app_handle: tauri::AppHandle<R>
) {
    thread::spawn(move || {
        let mut buffer = [0; 65535]; 
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((size, _origen)) => {
                    let datos_recibidos = &buffer[..size];
                    match session.allocate_send_packet(size as u16) {
                        Ok(mut packet) => {
                            packet.bytes_mut().copy_from_slice(datos_recibidos);
                            session.send_packet(packet);
                            let _ = app_handle.emit("trafico-entrada", size);
                        },
                        Err(_) => println!("Error Wintun"),
                    }
                },
                Err(e) => {
                    if let Some(10054) = e.raw_os_error() { continue; }
                    println!("Error UDP: {}", e);
                }
            }
        }
    });
}

// --- NEGOCIAR CON EL ROUTER (UPnP) ---
#[tauri::command]
async fn activar_upnp(puerto_local: u16) -> String {
    // PASO 1: Descubrir mi propia IP Local (LAN)
    // Hacemos un truco: conectamos un socket "falso" a Google DNS.
    // No envía datos, solo sirve para que el sistema nos diga qué IP estamos usando.
    let ip_local = match UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => {
            if let Err(_) = socket.connect("8.8.8.8:80") {
                return "Error: No tienes internet para detectar tu IP".to_string();
            }
            match socket.local_addr() {
                Ok(addr) => addr.ip(),
                Err(_) => return "Error detectando IP Local".to_string(),
            }
        },
        Err(_) => return "Error creando socket de detección".to_string(),
    };

    // PASO 2: Buscar el Router
    match search_gateway(SearchOptions::default()) {
        Ok(gateway) => {
            // Obtener la IP Pública (WAN)
            let ip_publica = match gateway.get_external_ip() {
                Ok(ip) => ip,
                Err(_) => return "Router encontrado, pero no dio IP Pública".to_string(),
            };
            
            // PASO 3: Construir la dirección completa (CORRECCIÓN DEL ERROR)
            // El router necesita IP_LOCAL + PUERTO
            let direccion_local = SocketAddr::new(ip_local, puerto_local);

            // PASO 4: Pedir que abra el puerto
            match gateway.add_port(
                igd_next::PortMappingProtocol::UDP,
                puerto_local,      // Puerto Externo (Internet)
                direccion_local,   // Dirección Interna (Tu PC) <-- AQUÍ ESTABA EL ERROR
                0,                 // Duración (0 = Infinito)
                "Mimic Link Tunnel"
            ) {
                Ok(_) => return format!("{}", ip_publica), // ¡ÉXITO!
                Err(e) => return format!("Router rechazó abrir el puerto: {}", e),
            }
        },
        Err(e) => return format!("No se encontró router UPnP: {}", e),
    }
}

// --- COMANDO PRINCIPAL ---
#[tauri::command]
fn conectar_tunel(ip_destino: String, puerto_local: String, ip_virtual: String, app_handle: tauri::AppHandle) -> String {
    
    // 1. Cargar Driver
    let wintun = unsafe { wintun::load_from_path("wintun.dll") };
    if wintun.is_err() { return "ERROR CRÍTICO: No encuentro wintun.dll".to_string(); }
    let wintun = wintun.unwrap();

    // 2. Crear Adaptador
    let adapter = match wintun::Adapter::create(&wintun, "MimicV2", NOMBRE_ADAPTADOR, None) {
        Ok(a) => a,
        Err(e) => return format!("Error creando adaptador: {:?}", e),
    };

    // 3. Iniciar Sesión
    let session = match adapter.start_session(0x400000) {
        Ok(s) => Arc::new(s),
        Err(e) => return format!("Error iniciando sesión: {:?}", e),
    };

    // 4. Configurar IP de Windows
    let _ = Command::new("netsh")
        .args(&["interface", "ip", "set", "address", &format!("name=\"{}\"", NOMBRE_ADAPTADOR), "static", &ip_virtual, TUNEL_MASK])
        .output();

    // 5. Preparar Sockets
    let socket_local = match UdpSocket::bind(format!("0.0.0.0:{}", puerto_local)) {
        Ok(s) => s,
        Err(e) => return format!("Puerto local ocupado: {}", e),
    };
    
    let socket_salida = socket_local.try_clone().unwrap();

    // 6. Lanzar Hilos
    iniciar_hilo_entrada(session.clone(), socket_local, app_handle.clone());
    iniciar_hilo_salida(session, socket_salida, ip_destino.clone(), app_handle);

    format!("CONECTADO: Túnel activo en {}", ip_virtual)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![conectar_tunel, activar_upnp])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
