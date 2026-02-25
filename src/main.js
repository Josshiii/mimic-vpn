const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

async function conectar() {
  const ipVirtualInput = document.querySelector("#ip-virtual"); // NUEVO
  const ipInput = document.querySelector("#ip-destino");
  const puertoInput = document.querySelector("#puerto-local");
  const status = document.querySelector("#status");
  
  status.textContent = "Configurando red...";
  status.style.color = "yellow";

  try {
    // Enviamos los 3 datos a Rust
    const respuesta = await invoke("conectar_tunel", { 
      ipVirtual: ipVirtualInput.value, // Esto se convierte en ip_virtual en Rust
      ipDestino: ipInput.value,
      puertoLocal: puertoInput.value
    });
    
    status.textContent = respuesta;
    status.style.color = "#00ff00";

  } catch (error) {
    console.error(error);
    status.textContent = "FALLO: " + error;
    status.style.color = "red";
  }
}

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
      console.log("Luces off: " + e);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const btn = document.querySelector("#btn-conectar");
  if(btn) {
      btn.addEventListener("click", conectar);
      iniciarLuces();
  }
});
