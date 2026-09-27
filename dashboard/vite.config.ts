import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The dashboard calls the API with relative paths, so the dev server forwards
// them instead of the browser talking to the backend directly. The default
// target is nginx, not the backend: the backend requires a client certificate
// (RF-01) and a browser has nowhere to put a private key, so nginx is the only
// process that can reach it. Point this at the backend only when running it with
// certificates a client can present.
const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:3000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: BACKEND, changeOrigin: true },
      "/healthz": { target: BACKEND, changeOrigin: true },
      "/readyz": { target: BACKEND, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
