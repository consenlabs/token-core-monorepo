import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// P6-d: Claude/OpenAI 在瀏覽器環境下受 CORS 限制，無法直接呼叫。
// 透過 Vite dev/preview server proxy，將 /api/claude/* 與 /api/openai/*
// 轉發至對應的 API endpoint，瀏覽器只看到 same-origin 請求，繞過 CORS。
// 注意：此 proxy 僅在 Vite server 執行期間（npm run dev / npm run preview）有效；
// 靜態部署時需另外設置 nginx/reverse proxy 或改用後端 BFF。
// P6-m: Only Groq requires a proxy (CORS restriction). Gemini supports direct browser calls.
const aiProxyRules = {
  "/api/groq": {
    target: "https://api.groq.com",
    changeOrigin: true,
    rewrite: (path: string) => path.replace(/^\/api\/groq/, ""),
  },
};

export default defineConfig({
  plugins: [react()],

  server: {
    host: true, // 等同無 "dev": "vite --host", 指令
    // 原始碼位在實體機（Host），而 Vite 執行在 Linux 容器內。在某些情況下（特別是 Docker Desktop），Linux 的 inotify 機制無法接收到來自 Host 檔案系統的變更事件。
    watch: {
      usePolling: true, // 強制使用輪詢監聽檔案變更
      interval: 100, // 每 100ms 檢查一次
    },
    proxy: aiProxyRules,
  },

  preview: {
    proxy: aiProxyRules,
  },

  test: {
    setupFiles: ["src/test/setup.ts"],
  },
});
