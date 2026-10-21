import { defineStore } from 'pinia'
import { authApi } from '../api/endpoints'

const KEY = 'ctydash.user'

export const useAuthStore = defineStore('auth', {
  state: () => ({ user: null, ready: false }),
  getters: {
    isLogin: (s) => !!s.user,
    isAdmin: (s) => s.user?.role === 'admin',
  },
  actions: {
    restore() {
      if (this.user) return
      try {
        this.user = JSON.parse(localStorage.getItem(KEY) || 'null')
      } catch {
        this.user = null
      }
    },
    set(u) {
      this.user = u
      if (u) localStorage.setItem(KEY, JSON.stringify(u))
      else localStorage.removeItem(KEY)
    },
    /** 首次路由前调用：用 cookie 会话换取当前用户；后端不可达时保留缓存用户 */
    async ensureReady() {
      if (this.ready) return
      this.restore()
      try {
        const me = await authApi.me()
        if (me && me.username) this.set(me)
      } catch {
        /* 401 或后端离线：保留本地缓存供查看 */
      } finally {
        this.ready = true
      }
    },
    async login(username, password) {
      const u = await authApi.login(username, password)
      this.set(u)
      return u
    },
    async logout() {
      try {
        await authApi.logout()
      } catch {
        /* 注销失败也照常清态 */
      }
      this.set(null)
    },
  },
})
