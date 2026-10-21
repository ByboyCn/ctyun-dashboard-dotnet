<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusBadge from './StatusBadge.vue'
import TaskBar from './TaskBar.vue'
import AccountSettingsDialog from './AccountSettingsDialog.vue'
import PointsDialog from './PointsDialog.vue'
import DesktopsDrawer from './DesktopsDrawer.vue'
import CaptchaReloginDialog from './CaptchaReloginDialog.vue'
import SmsDeviceDialog from './SmsDeviceDialog.vue'
import { api, FEATURES, TASK_KEYS, TASK_LABELS } from '../api/endpoints'
import { errMsg, fmtCountdown, statusOf, taskOf } from '../utils/format'

const props = defineProps({
  card: { type: Object, required: true },
  platform: { type: String, required: true },
})
const emit = defineEmits(['refresh', 'enter-wall'])

const feat = computed(() => FEATURES[props.platform] || {})
const status = computed(() => statusOf(props.card))
const statusTip = computed(() => props.card.statusText || props.card.lastError || '')
// 30060/30090 风控信号：服务端要求图形验证码重新登录
const needCaptchaRelogin = computed(() => /需要图形验证码/.test(String(props.card?.statusText || '')))
const desktops = computed(() => props.card.desktops || [])
const tasks = computed(() => ({
  sign: taskOf(props.card, 'sign'),
  ai: taskOf(props.card, 'ai'),
  hang: taskOf(props.card, 'hang'),
}))

// ===== 脉冲倒计时：服务端给 next_pulse_in_sec，本地每秒递减 =====
const remain = ref(Number(props.card.nextPulseInSec) || 0)
watch(
  () => props.card.nextPulseInSec,
  (v) => {
    remain.value = Number(v) || 0
  },
)
let timer = null
onMounted(() => {
  timer = setInterval(() => {
    if (remain.value > 0) remain.value--
  }, 1000)
})
onBeforeUnmount(() => clearInterval(timer))

// ===== 操作 =====
const syncing = ref(false)
const busy = ref(false)
const accId = computed(() => String(props.card.id || ''))

async function doSync() {
  syncing.value = true
  try {
    await api(props.platform).sync(accId.value)
    ElMessage.success('已触发同步，稍后刷新')
    emit('refresh')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    syncing.value = false
  }
}

async function doRelogin() {
  busy.value = true
  try {
    await api(props.platform).relogin(accId.value)
    ElMessage.success('已用已存凭据重新登录')
    emit('refresh')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    busy.value = false
  }
}

async function doTask(key) {
  busy.value = true
  try {
    await api(props.platform).taskRun(accId.value, key)
    ElMessage.success(`「${TASK_LABELS[key]}」任务已下发`)
    emit('refresh')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    busy.value = false
  }
}

async function doRemove() {
  try {
    await ElMessageBox.confirm(
      `确定删除账号「${props.card.name || props.card.userMasked || accId.value}」吗？已存凭据将被清除。`,
      '删除账号',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  busy.value = true
  try {
    await api(props.platform).remove(accId.value)
    ElMessage.success('账号已删除')
    emit('refresh')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    busy.value = false
  }
}

function onMore(cmd) {
  if (cmd === 'settings') settingsVisible.value = true
  else if (cmd === 'points' && feat.value.points) pointsVisible.value = true
  else if (cmd === 'relogin') {
    // 30060/30090 风控：服务端要求图形验证码 → 走「验证码重新验证」弹窗而非直接 relogin
    if (needCaptchaRelogin.value) captchaReloginVisible.value = true
    else doRelogin()
  } else if (cmd === 'sms-device') smsDeviceVisible.value = true
  else if (cmd === 'remove') doRemove()
}

// ===== 卡片单击 / 双击（单击=桌面抽屉，双击=设备墙；与拖拽、内部控件互斥） =====
let clickTimer = null
function isInteractive(target) {
  return !!target?.closest?.('button, a, .el-dropdown, .el-switch, .el-checkbox, input, .el-dialog')
}
function onBodyClick(e) {
  if (isInteractive(e.target)) return
  clearTimeout(clickTimer)
  clickTimer = setTimeout(() => {
    // 单击卡片：有桌面能力的打开桌面抽屉，否则打开账号设置
    if (feat.value.desktops) drawerVisible.value = true
    else settingsVisible.value = true
  }, 250)
}
function onBodyDblClick(e) {
  if (isInteractive(e.target)) return
  clearTimeout(clickTimer)
  emit('enter-wall')
}
onBeforeUnmount(() => clearTimeout(clickTimer))

// ===== 弹窗开关 =====
const settingsVisible = ref(false)
const pointsVisible = ref(false)
const drawerVisible = ref(false)
const captchaReloginVisible = ref(false)
const smsDeviceVisible = ref(false)
</script>

<template>
  <div
    class="acct-card"
    :class="{ 'is-paused': status === 'paused' }"
    title="单击：桌面管理 · 双击：设备墙"
    @click="onBodyClick"
    @dblclick="onBodyDblClick"
  >
    <div class="ac-head">
      <div class="ac-name" :title="card.userMasked">
        {{ card.name || '未命名账号' }}
        <span class="ac-user">{{ card.userMasked || card.owner || '' }}</span>
      </div>
      <div class="ac-head-right">
        <StatusBadge :status="status" :tip="statusTip" />
        <el-dropdown trigger="click" @command="onMore">
          <span class="ac-more" title="更多操作">⋯</span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="settings">账号设置</el-dropdown-item>
              <el-dropdown-item v-if="feat.points" command="points">积分与兑换</el-dropdown-item>
              <el-dropdown-item command="relogin" :class="{ 'menu-item-warn': needCaptchaRelogin }">
                {{ needCaptchaRelogin ? '⚠ 验证码重新验证' : '重新登录' }}
              </el-dropdown-item>
              <el-dropdown-item v-if="needCaptchaRelogin" command="sms-device" class="menu-item-warn">
                📱 短信验证设备
              </el-dropdown-item>
              <el-dropdown-item command="remove" divided>删除账号</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </div>

    <div class="ac-stats">
      <div class="stat">
        <span class="stat-num">{{ card.points ?? 0 }}</span>
        <span class="stat-label">积分</span>
      </div>
      <div class="stat">
        <span class="stat-num">{{ desktops.length }}</span>
        <span class="stat-label">桌面</span>
      </div>
      <div class="stat">
        <span class="stat-num" :title="card.statusText || ''">{{ fmtCountdown(remain) }}</span>
        <span class="stat-label">下次脉冲</span>
      </div>
    </div>

    <div class="ac-tasks">
      <TaskBar label="打卡" :task="tasks.sign" />
      <TaskBar label="AI" :task="tasks.ai" />
      <TaskBar label="挂机" :task="tasks.hang" />
    </div>

    <div v-if="card.lastError" class="ac-error" :title="card.lastError">{{ card.lastError }}</div>

    <div class="ac-actions">
      <el-button v-if="feat.desktops" size="small" @click="drawerVisible = true">远程桌面</el-button>
      <el-button size="small" @click="emit('enter-wall')">设备墙</el-button>
      <el-button size="small" :loading="syncing" @click="doSync">同步</el-button>
      <el-dropdown v-if="feat.tasks" trigger="click" @command="doTask">
        <el-button size="small" :loading="busy">任务 ▾</el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item v-for="k in TASK_KEYS" :key="k" :command="k">
              立即执行「{{ TASK_LABELS[k] }}」
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>

    <AccountSettingsDialog v-model="settingsVisible" :card="card" :platform="platform" @saved="emit('refresh')" />
    <PointsDialog v-if="feat.points" v-model="pointsVisible" :card="card" @saved="emit('refresh')" />
    <DesktopsDrawer
      v-if="feat.desktops"
      v-model="drawerVisible"
      :card="card"
      :platform="platform"
      @refreshed="emit('refresh')"
    />
    <CaptchaReloginDialog v-model="captchaReloginVisible" :card="card" @refreshed="emit('refresh')" />
    <SmsDeviceDialog v-model="smsDeviceVisible" :card="card" @refreshed="emit('refresh')" />
  </div>
</template>
