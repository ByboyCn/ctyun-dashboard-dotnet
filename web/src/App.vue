<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from './stores/auth'
import { useThemeStore } from './stores/theme'
import { authApi, systemApi } from './api/endpoints'
import { errMsg, fmtUptime } from './utils/format'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const theme = useThemeStore()

// 登录页不套控制台框架
const bare = computed(() => route.meta.public === true)

const navs = [
  { path: '/', label: '仪表盘' },
  { path: '/logs', label: '实时日志' },
  { path: '/settings', label: '系统设置', admin: true },
  { path: '/users', label: '用户管理', admin: true },
]
const visibleNavs = computed(() => navs.filter((n) => !n.admin || auth.isAdmin))
const pageTitle = computed(() => route.meta.title || '')

// 侧栏底部系统信息（后端离线时静默降级）
const sysInfo = ref(null)
async function loadSys() {
  try {
    sysInfo.value = await systemApi.info()
  } catch {
    sysInfo.value = null
  }
}
onMounted(loadSys)

// 修改密码
const pwdVisible = ref(false)
const pwdLoading = ref(false)
const pwdForm = reactive({ oldPwd: '', newPwd: '', newPwd2: '' })
function openPwd() {
  Object.assign(pwdForm, { oldPwd: '', newPwd: '', newPwd2: '' })
  pwdVisible.value = true
}
async function submitPwd() {
  if (!pwdForm.oldPwd || !pwdForm.newPwd) return ElMessage.warning('请填写完整')
  if (pwdForm.newPwd !== pwdForm.newPwd2) return ElMessage.warning('两次输入的新密码不一致')
  pwdLoading.value = true
  try {
    await authApi.changePwd(pwdForm.oldPwd, pwdForm.newPwd)
    ElMessage.success('密码已修改')
    pwdVisible.value = false
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    pwdLoading.value = false
  }
}

async function doLogout() {
  await auth.logout()
  ElMessage.success('已退出登录')
  router.push('/login')
}

function onUserCmd(cmd) {
  if (cmd === 'pwd') openPwd()
  else if (cmd === 'logout') doLogout()
}
</script>

<template>
  <router-view v-if="bare" />

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="logo">
        <span class="logo-dot" />
        <div>
          <div class="logo-title">天翼云保活控制台</div>
          <div class="logo-sub">CtyunDashboard</div>
        </div>
      </div>
      <nav class="nav">
        <router-link
          v-for="n in visibleNavs"
          :key="n.path"
          :to="n.path"
          class="nav-item"
          :class="{ exact: n.path === '/' }"
        >
          {{ n.label }}
        </router-link>
      </nav>
      <div class="sidebar-foot">
        <template v-if="sysInfo">
          <div>v{{ sysInfo.version }} · {{ sysInfo.runtime }}</div>
          <div>已运行 {{ fmtUptime(sysInfo.uptimeSec) }} · 账号 {{ sysInfo.accountCount }}</div>
        </template>
        <div v-else class="muted">后端未连接（127.0.0.1:8571）</div>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="topbar-title">{{ pageTitle }}</div>
        <div class="topbar-right">
          <el-tooltip :content="theme.mode === 'dark' ? '切换到亮色主题' : '切换到暗色主题'" placement="bottom">
            <el-switch
              :model-value="theme.mode === 'dark'"
              inline-prompt
              active-text="暗"
              inactive-text="亮"
              @change="theme.toggle()"
            />
          </el-tooltip>
          <el-dropdown trigger="click" @command="onUserCmd">
            <span class="user-chip">
              <span class="user-name">{{ auth.user?.username || '未登录' }}</span>
              <span class="user-role" :class="auth.isAdmin ? 'is-admin' : ''">
                {{ auth.user?.role === 'admin' ? '管理员' : '用户' }}
              </span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="pwd">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>
      <main class="page">
        <router-view />
      </main>
    </div>
  </div>

  <el-dialog v-model="pwdVisible" title="修改密码" width="420px" append-to-body>
    <el-form label-width="90px">
      <el-form-item label="原密码">
        <el-input v-model="pwdForm.oldPwd" type="password" show-password autocomplete="off" />
      </el-form-item>
      <el-form-item label="新密码">
        <el-input v-model="pwdForm.newPwd" type="password" show-password autocomplete="off" />
      </el-form-item>
      <el-form-item label="确认新密码">
        <el-input v-model="pwdForm.newPwd2" type="password" show-password autocomplete="off" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="pwdVisible = false">取消</el-button>
      <el-button type="primary" :loading="pwdLoading" @click="submitPwd">保存</el-button>
    </template>
  </el-dialog>
</template>
