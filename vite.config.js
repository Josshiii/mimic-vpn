import { defineConfig } from "vite";

// https://vitejs.dev/config/
export default defineConfig({
  // Vite opciones adaptadas para Tauri
  clearScreen: false,
  server: {
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    // Tauri usa Chromium en Windows
    target: "chrome105",
    // No minificar en modo debug para ver errores si los hay
    minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
