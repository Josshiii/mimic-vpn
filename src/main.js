const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

// --- SISTEMA DE MEMORIA (Persistencia) ---
function cargarConfiguracion() {
  const savedIpVirtual = localStorage.getItem("mimic_ip_virtual");
  const savedIpDestino = localStorage.getItem("mimic_ip_destino");

  if (savedIpVirtual) {
    document.querySelector("#ip-virtual").value = savedIpVirtual;
  }
  if (savedIpDestino) {
    document.querySelector("#ip-destino").value = savedIpDestino;
  }
}

function guardarConfiguracion() {
  const ipVirtual = document.querySelector("#ip-virtual").value;
  const ipDestino = document.querySelector("#ip-destino").value;

  localStorage.setItem("mimic_ip_virtual", ipVirtual);
  localStorage.setItem("mimic_ip_destino", ipDestino);
}

// --- SISTEMA DE VALIDACIÓN (Regex) ---
function esIPValida(texto) {
  // Esta expresión regular verifica si parece una IP (ej: 192.168.1.1)
  // Acepta formato IP o IP:PUERTO
  if (!texto) return false;
  // Simplemente verificamos que tenga números y puntos, y longitud mínima
  return texto.length >= 7 && texto.includes(".");
}

// --- LÓGICA PRINCIPAL ---
async function conectar() {
  const ipVirtualInput = document.querySelector("#ip-virtual");
  const ipInput = document.querySelector("#ip-destino");
  const puertoInput = document.querySelector("#puerto-local");
  const status = document.querySelector("#status");
  
  // 1. VALIDACIÓN PREVENTIVA
  if (!esIPValida(ipVirtualInput.value) || !esIPValida(ipInput.value)) {
    status.textContent = "ERROR: Formato de IP inválido";
    status.style.color = "#ed4245"; // Rojo Discord
    return; // Detenemos la ejecución aquí
  }

  status.textContent = "Estableciendo enlace...";
  status.style.color = "#faa61a"; // Amarillo Carga

  // 2. GUARDAR DATOS (Memoria)
  guardarConfiguracion();

  try {
    const respuesta = await invoke("conectar_tunel", { 
      ipVirtual: ipVirtualInput.value,
      ipDestino: ipInput.value,
      puertoLocal: puertoInput.value
    });
    
    status.textContent = respuesta;
    status.style.color = "#3ba55c"; // Verde Éxito

  } catch (error) {
    console.error(error);
    status.textContent = "FALLO: " + error;
    status.style.color = "#ed4245";
  }
}

async function iniciarLuces() {
  const ledTx = document.querySelector("#led-tx");
  const ledRx = document.querySelector("#led-rx");

  try {
      // Usamos clases CSS para activar las luces (más limpio)
      await listen('trafico-salida', () => {
        ledTx.classList.add("active-tx");
        setTimeout(() => ledTx.classList.remove("active-tx"), 100);
      });

      await listen('trafico-entrada', () => {
        ledRx.classList.add("active-rx");
        setTimeout(() => ledRx.classList.remove("active-rx"), 100);
      });
  } catch (e) {
      console.log("Sistema de luces en espera: " + e);
  }
}

// INICIALIZACIÓN
window.addEventListener("DOMContentLoaded", () => {
  // Cargar datos guardados al abrir
  cargarConfiguracion();

  const btn = document.querySelector("#btn-conectar");
  if(btn) {
      btn.addEventListener("click", conectar);
      iniciarLuces();
  }
});

// ... código anterior ...

// NUEVA FUNCIÓN: Activar UPnP
async function abrirPuertos() {
  const btn = document.querySelector("#btn-upnp");
  const inputPublica = document.querySelector("#ip-publica");
  const puerto = document.querySelector("#puerto-local").value;

  btn.textContent = "Negociando...";
  btn.disabled = true;

  try {
    // Llamamos a Rust para que hable con el router
    // Convertimos el puerto a número entero (parseInt)
    const ipPublica = await invoke("activar_upnp", { puertoLocal: parseInt(puerto) });
    
    if (ipPublica.includes("Fallo") || ipPublica.includes("No se encontró")) {
       inputPublica.value = "Error UPnP";
       btn.textContent = "Fallo Manual";
       btn.style.backgroundColor = "#ed4245";
       alert("Tu router no soporta UPnP o está desactivado. Tendrás que usar Radmin o abrir puertos manualmente.\n\nError: " + ipPublica);
    } else {
       // ÉXITO TOTAL
       inputPublica.value = ipPublica + ":" + puerto;
       btn.textContent = "¡Visible en Internet!";
       btn.style.backgroundColor = "#3ba55c";
       
       // Copiar al portapapeles automáticamente
       navigator.clipboard.writeText(inputPublica.value);
       alert("¡Puerto Abierto!\n\nTu IP Pública es: " + ipPublica + "\n\nSe ha copiado al portapapeles. Pásasela a tu amigo.");
    }

  } catch (error) {
    console.error(error);
    btn.textContent = "Error";
  }
}

// ... en el addEventListener ...
window.addEventListener("DOMContentLoaded", () => {
  // ... lo anterior ...
  const btnUpnp = document.querySelector("#btn-upnp");
  if(btnUpnp) btnUpnp.addEventListener("click", abrirPuertos);
});
