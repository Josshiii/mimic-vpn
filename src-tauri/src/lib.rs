use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use tauri::Emitter;

const TUNEL_MASK: &str = "255.255.255.0";
const NOMBRE_ADAPTADOR: &str = "MimicVPN";

// HILO 1: SALIDA (De Windows hacia Internet)
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
                            Err(e) => println!("Error enviando a amigo: {}", e),
                        }
                    }
                },
                Err(_) => break,
            }
        }
    });
}

// HILO 2: ENTRADA (De Internet hacia Windows)
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
                        Err(_) => println!("Error al asignar memoria en Wintun"),
                    }
                },
                Err(e) => {
                    if let Some(10054) = e.raw_os_error() { continue; }
                    println!("Error recibiendo UDP: {}", e);
                }
            }
        }
    });
}

// AQUI ESTA EL CAMBIO: Ahora pedimos ip_virtual como argumento
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

    // 4. Configurar IP de Windows (USAMOS LA VARIABLE ip_virtual)
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

    format!("CONECTADO: Túnel activo en {}. Destino: {}", ip_virtual, ip_destino)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![conectar_tunel])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
