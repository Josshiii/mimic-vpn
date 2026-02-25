// Acceso al núcleo de Tauri
// NOTA: Si window.__TAURI__ falla, asegúrate de que tauri.conf.json tenga "withGlobalTauri": true
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

async function conectar() {
  const ipInput = document.querySelector("#ip-destino");
  const puertoInput = document.querySelector("#puerto-local");
  const status = document.querySelector("#status");
  
  status.textContent = "Intentando conectar...";
  status.style.color = "yellow";

  try {
    // CORRECCIÓN AQUÍ: Tauri convierte automáticamente snake_case a camelCase
    const respuesta = await invoke("conectar_tunel", { 
      ipDestino: ipInput.value,     // Rust espera ip_destino, pero aquí se llama ipDestino
      puertoLocal: puertoInput.value // Rust espera puerto_local, pero aquí se llama puertoLocal
    });
    
    status.textContent = respuesta;
    status.style.color = "#00ff00"; // Verde Éxito

  } catch (error) {
    console.error(error);
    status.textContent = "FALLO: " + error;
    status.style.color = "red";
  }
}

// Sistema de Luces (LEDs)
async function iniciarLuces() {
  const ledTx = document.querySelector("#led-tx");
  const ledRx = document.querySelector("#led-rx");

  try {
      await listen('trafico-salida', (event) => {
        ledTx.style.backgroundColor = "#00ff00"; 
        setTimeout(() => ledTx.style.backgroundColor = "#333", 50);
      });

      await listen('trafico-entrada', (event) => {
        ledRx.style.backgroundColor = "#0055ff"; 
        setTimeout(() => ledRx.style.backgroundColor = "#333", 50);
      });
  } catch (e) {
      console.log("Sistema de luces no disponible aún: " + e);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const btn = document.querySelector("#btn-conectar");
  if(btn) {
      btn.addEventListener("click", conectar);
      iniciarLuces();
  }
});
