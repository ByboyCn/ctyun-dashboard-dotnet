<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '../stores/auth'
import { errMsg } from '../utils/format'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function submit() {
  if (loading.value) return   // 防重入：Enter 原生提交与按钮可能并发触发
  if (!form.username || !form.password) return ElMessage.warning('请输入用户名和密码')
  loading.value = true
  try {
    const u = await auth.login(form.username.trim(), form.password)
    ElMessage.success(`欢迎，${u.username}`)
    router.push(String(route.query.redirect || '/'))
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="login-logo">
        <div class="big">天翼云保活控制台</div>
        <div class="small">CTYUN DASHBOARD</div>
      </div>
      <el-form @submit.prevent="submit">
        <el-form-item>
          <el-input
            v-model="form.username"
            placeholder="用户名"
            size="large"
            autofocus
            autocomplete="username"
          />
        </el-form-item>
        <el-form-item>
          <el-input
            v-model="form.password"
            type="password"
            show-password
            placeholder="密码"
            size="large"
            autocomplete="current-password"
          />
        </el-form-item>
        <el-button class="login-btn" type="primary" size="large" native-type="submit" :loading="loading">
          登 录
        </el-button>
      </el-form>
    </div>
    <div class="login-foot">CtyunDashboard · 前后端分离 · Protobuf over HTTP</div>
  </div>
</template>
