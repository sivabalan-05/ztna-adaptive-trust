import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 5173,
    // Vite runs in a container while the browser is on the host, so the HMR
    // websocket has to be told where to reconnect.
    watch: { usePolling: true },
  },
});
