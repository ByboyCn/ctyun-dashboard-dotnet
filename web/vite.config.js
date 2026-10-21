import vue from '@vitejs/plugin-vue'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

// web/ 的上级目录（CtyunDashboard）里有唯一契约源 proto/api.proto，
// 源码以 `?raw` 直接导入它，dev server 需要放行上级目录。
const projectRoot = fileURLToPath(new URL('..', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      // 前后端分离：开发期把 /api 转发到后端
      '/api': {
        target: 'http://127.0.0.1:8571',
        changeOrigin: true,
      },
    },
    fs: { allow: [projectRoot] },
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 2000,
  },
})
