import { defineConfig } from "vite";
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  resolve: {alias: {"@": fileURLToPath(new URL("./src", import.meta.url))}},
  plugins: [react(), tailwindcss()],
  server: { proxy: { "/api": "http://127.0.0.1:8790" } },
  build: { sourcemap: false },
});
