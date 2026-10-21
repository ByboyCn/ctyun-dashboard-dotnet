import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

// 用 hash 模式：单体部署时后端直接托管 web/dist 静态目录，无需 SPA 回退路由
const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('../views/LoginView.vue'),
    meta: { public: true, title: '登录' },
  },
  { path: '/', name: 'dashboard', component: () => import('../views/DashboardView.vue'), meta: { title: '仪表盘' } },
  {
    path: '/devices/:accId',
    name: 'devices',
    component: () => import('../views/DeviceWallView.vue'),
    meta: { title: '设备墙' },
  },
  { path: '/logs', name: 'logs', component: () => import('../views/LogsView.vue'), meta: { title: '实时日志' } },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/SettingsView.vue'),
    meta: { admin: true, title: '系统设置' },
  },
  {
    path: '/users',
    name: 'users',
    component: () => import('../views/UsersView.vue'),
    meta: { admin: true, title: '用户管理' },
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach(async (to) => {
  const auth = useAuthStore()
  await auth.ensureReady()
  if (!to.meta.public && !auth.isLogin) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.meta.admin && !auth.isAdmin) return { path: '/' }
  if (to.path === '/login' && auth.isLogin) return { path: '/' }
  return true
})

export default router
