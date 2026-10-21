import { defineStore } from 'pinia'

const KEY = 'ctydash.theme'

/** 亮/暗双主题：默认暗色，用户选择持久化 */
export const useThemeStore = defineStore('theme', {
  state: () => ({ mode: localStorage.getItem(KEY) === 'light' ? 'light' : 'dark' }),
  actions: {
    apply() {
      document.documentElement.classList.toggle('dark', this.mode === 'dark')
    },
    init() {
      this.apply()
    },
    toggle() {
      this.mode = this.mode === 'dark' ? 'light' : 'dark'
      localStorage.setItem(KEY, this.mode)
      this.apply()
    },
  },
})
