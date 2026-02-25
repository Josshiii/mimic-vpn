// Accedemos al núcleo de Tauri
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

async function conectar() {
  const ipInput = document.querySelector("#ip-destino");
  const puertoInput = document.querySelector("#puerto-local");
  const status = document.querySelector("#status");
  
  // 1. Feedback visual inmediato
  status.textContent = "Intentando conectar...";
  status.style.color = "yellow";

  try {
    // 2. Llamada a Rust (Usamos los nombres EXACTOS de Rust: snake_case)
    const respuesta = await invoke("conectar_tunel", { 
      ip_destino: ipInput.value, 
      puerto_local: puertoInput.value 
    });
    
    // 3. Éxito
    status.textContent = respuesta;
    status.style.color = "#00ff00"; // Verde Hacker

  } catch (error) {
    // 4. Error
    console.error(error);
    status.textContent = "FALLO: " + error;
    status.style.color = "red";
  }
}

// Sistema de Luces (LEDs)
async function iniciarLuces() {
  const ledTx = document.querySelector("#led-tx");
  const ledRx = document.querySelector("#led-rx");

  // Escuchamos eventos desde Rust
  await listen('trafico-salida', (event) => {
    ledTx.style.backgroundColor = "#00ff00"; 
    setTimeout(() => ledTx.style.backgroundColor = "#333", 50);
  });

  await listen('trafico-entrada', (event) => {
    ledRx.style.backgroundColor = "#0055ff"; 
    setTimeout(() => ledRx.style.backgroundColor = "#333", 50);
  });
}

// Inicialización
window.addEventListener("DOMContentLoaded", () => {
  const btn = document.querySelector("#btn-conectar");
  if(btn) {
      btn.addEventListener("click", conectar);
      iniciarLuces();
  } else {
      console.error("No encontré el botón de conectar");
  }
});
