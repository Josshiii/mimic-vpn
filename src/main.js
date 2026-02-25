const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

async function conectar() {
  const ip = document.querySelector("#ip-destino").value;
  const puerto = document.querySelector("#puerto-local").value;
  const status = document.querySelector("#status");
  
  status.textContent = "Iniciando motores...";

  try {
    const respuesta = await invoke("conectar_tunel", { 
      ipDestino: ip, 
      puertoLocal: puerto 
    });
    status.textContent = respuesta;
    status.style.color = "#00ff00";
  } catch (error) {
    status.textContent = "ERROR: " + error;
    status.style.color = "red";
  }
}

// Sistema de Luces (LEDs)
async function iniciarLuces() {
  const ledTx = document.querySelector("#led-tx");
  const ledRx = document.querySelector("#led-rx");

  await listen('trafico-salida', () => {
    ledTx.style.backgroundColor = "#00ff00"; // Enciende Verde
    setTimeout(() => ledTx.style.backgroundColor = "#333", 50); // Apaga rápido
  });

  await listen('trafico-entrada', () => {
    ledRx.style.backgroundColor = "#0055ff"; // Enciende Azul
    setTimeout(() => ledRx.style.backgroundColor = "#333", 50);
  });
}

window.addEventListener("DOMContentLoaded", () => {
  document.querySelector("#btn-conectar").addEventListener("click", conectar);
  iniciarLuces();
});