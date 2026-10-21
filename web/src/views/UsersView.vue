<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useAuthStore } from '../stores/auth'
import { userApi } from '../api/endpoints'
import { errMsg, fmtDateTime } from '../utils/format'

const auth = useAuthStore()
const items = ref([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const d = await userApi.list()
    items.value = d.items || []
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}
onMounted(load)

const isSelf = (row) => String(row.id) === String(auth.user?.id ?? '') || row.username === auth.user?.username

// 新增用户
const addVisible = ref(false)
const addLoading = ref(false)
const addForm = reactive({ username: '', password: '', role: 'user' })

async function submitAdd() {
  if (!addForm.username || !addForm.password) return ElMessage.warning('请填写用户名和密码')
  addLoading.value = true
  try {
    await userApi.create(addForm.username.trim(), addForm.password, addForm.role)
    ElMessage.success('用户已创建')
    addVisible.value = false
    Object.assign(addForm, { username: '', password: '', role: 'user' })
    load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    addLoading.value = false
  }
}

// 重置密码
const resetVisible = ref(false)
const resetLoading = ref(false)
const resetForm = reactive({ id: '', username: '', password: '' })

function openReset(row) {
  Object.assign(resetForm, { id: String(row.id), username: row.username, password: '' })
  resetVisible.value = true
}

async function submitReset() {
  if (!resetForm.password) return ElMessage.warning('请输入新密码')
  resetLoading.value = true
  try {
    await userApi.resetPwd(resetForm.id, resetForm.password)
    ElMessage.success(`已重置 ${resetForm.username} 的密码`)
    resetVisible.value = false
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    resetLoading.value = false
  }
}

async function doRemove(row) {
  if (isSelf(row)) return ElMessage.warning('不能删除当前登录的用户')
  try {
    await ElMessageBox.confirm(`确定删除用户「${row.username}」吗？`, '删除用户', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  try {
    await userApi.remove(String(row.id))
    ElMessage.success('用户已删除')
    load()
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}
</script>

<template>
  <div>
    <div class="page-head">
      <span class="muted">管理员可添加用户、重置密码、删除用户</span>
      <el-button type="primary" @click="addVisible = true">添加用户</el-button>
    </div>

    <div class="panel" style="padding: 0">
      <el-table :data="items" v-loading="loading" style="width: 100%">
        <el-table-column prop="id" label="ID" width="90" />
        <el-table-column prop="username" label="用户名" min-width="160" />
        <el-table-column label="角色" width="120">
          <template #default="{ row }">
            <span class="status-badge" :class="row.role === 'admin' ? 'waitScan' : 'paused'">
              {{ row.role === 'admin' ? '管理员' : '用户' }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" min-width="180">
          <template #default="{ row }">{{ fmtDateTime(row.createdAt) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="220">
          <template #default="{ row }">
            <el-button size="small" @click="openReset(row)">重置密码</el-button>
            <el-button size="small" type="danger" plain :disabled="isSelf(row)" @click="doRemove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="addVisible" title="添加用户" width="420px">
      <el-form label-width="80px">
        <el-form-item label="用户名">
          <el-input v-model="addForm.username" maxlength="32" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="addForm.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-form-item label="角色">
          <el-radio-group v-model="addForm.role">
            <el-radio value="user">用户</el-radio>
            <el-radio value="admin">管理员</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="addVisible = false">取消</el-button>
        <el-button type="primary" :loading="addLoading" @click="submitAdd">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="resetVisible" :title="`重置密码 · ${resetForm.username}`" width="420px">
      <el-form label-width="80px" @submit.prevent="submitReset">
        <el-form-item label="新密码">
          <el-input v-model="resetForm.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resetVisible = false">取消</el-button>
        <el-button type="primary" :loading="resetLoading" @click="submitReset">重置</el-button>
      </template>
    </el-dialog>
  </div>
</template>
