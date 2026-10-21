<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, POWER_LABELS, powerActionsFor, resolveDesktopOpenUrl } from '../api/endpoints'
import { errMsg, fmtDateTime, formatInterval } from '../utils/format'

const props = defineProps({
  modelValue: Boolean,
  card: { type: Object, required: true },
  platform: { type: String, default: 'ctyun' },
})
const emit = defineEmits(['update:modelValue', 'refreshed'])

const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const accApi = computed(() => api(props.platform))
const actions = computed(() => powerActionsFor(props.platform, props.card))

const items = ref([])
const loading = ref(false)
const savingId = ref('')

async function load() {
  loading.value = true
  try {
    const d = await accApi.value.desktops(String(props.card.id || ''))
    items.value = (d.items || []).map((x) => ({ ...x, __power: '' }))
  } catch (e) {
    // 兜底：卡片上自带 desktops 快照
    items.value = (props.card.desktops || []).map((x) => ({ ...x, __power: '' }))
    ElMessage.warning(`桌面列表刷新失败（${errMsg(e)}），展示卡片缓存数据`)
  } finally {
    loading.value = false
  }
}

watch(visible, (v) => {
  if (v) load()
})

// per-VM 开关编辑副本：改动后点保存下发
function draft(d) {
  return {
    keepaliveEnabled: !!d.keepaliveEnabled,
    taskEnabled: !!d.taskEnabled,
    keepaliveInterval: Number(d.keepaliveInterval) || 30,
  }
}

async function savePrefs(d) {
  savingId.value = d.desktopId
  try {
    await accApi.value.prefs(String(props.card.id || ''), d.desktopId, draft(d))
    ElMessage.success(`桌面「${d.name || d.desktopId}」配置已保存`)
    emit('refreshed')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    savingId.value = ''
  }
}

const poweringId = ref('')
async function power(d, action) {
  poweringId.value = d.desktopId
  try {
    await accApi.value.power(String(props.card.id || ''), d.desktopId, action)
    ElMessage.success(`已对「${d.name || d.desktopId}」下发「${POWER_LABELS[action]}」`)
    emit('refreshed')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    poweringId.value = ''
  }
}

function onPowerCmd(d, action) {
  if (action === 'shutdown' || action === 'reboot') {
    ElMessageBox.confirm(
      `确定对桌面「${d.name || d.desktopId}」执行「${POWER_LABELS[action]}」吗？`,
      '电源操作',
      { type: 'warning', confirmButtonText: '执行', cancelButtonText: '取消' },
    )
      .then(() => power(d, action))
      .catch(() => {})
  } else {
    power(d, action)
  }
}

// 打开远程桌面：免密直通优先（open 接口，首次可能现场登录需几秒），失败降级 connectUrl
const openingId = ref('')
const blockedId = ref('') // 后端明确拒绝（如 ydpc 暂不支持网页直通）后短暂禁用按钮
async function openDesktop(d) {
  if (blockedId.value === d.desktopId) return
  openingId.value = d.desktopId
  try {
    const r = await resolveDesktopOpenUrl(props.platform, String(props.card.id || ''), d)
    if (r.via === 'direct') {
      window.open(r.url, '_blank', 'width=1280,height=800')
      ElMessage.success(`已打开${r.name ? `「${r.name}」` : ''}免密远程桌面`)
    } else if (r.via === 'blocked') {
      ElMessage.warning(r.detail || '当前平台暂不支持网页免密直通')
      blockedId.value = d.desktopId
      setTimeout(() => {
        if (blockedId.value === d.desktopId) blockedId.value = ''
      }, 5000)
    } else if (r.via === 'connectUrl') {
      window.open(r.url, '_blank')
      ElMessage.warning('免密直通未成功，已降级打开官方连接地址')
    } else {
      navigator.clipboard?.writeText(String(d.desktopId || '')).catch(() => {})
      ElMessage.error(`打开失败：${errMsg(r.err)}，已复制桌面ID`)
    }
  } finally {
    openingId.value = ''
  }
}
</script>

<template>
  <el-drawer v-model="visible" title="远程桌面 / 桌面管理" size="640px" append-to-body>
    <div v-loading="loading">
      <div class="form-hint" style="margin-bottom: 12px">
        账号：{{ card.name || card.userMasked }} · 共 {{ items.length }} 台桌面
      </div>

      <div v-for="d in items" :key="d.desktopId" class="panel" style="margin-bottom: 12px; padding: 12px 14px">
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap">
          <div>
            <b style="color: var(--text-1)">{{ d.name || d.desktopId }}</b>
            <span class="form-hint" style="margin-left: 8px">{{ d.spec || '' }}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 8px">
            <span
              class="status-badge"
              :class="(d.useStatusText || '').includes('运行') ? 'online' : 'paused'"
            >{{ d.useStatusText || '未知' }}</span>
            <el-button
              size="small"
              type="primary"
              plain
              :loading="openingId === d.desktopId"
              :disabled="blockedId === d.desktopId"
              @click="openDesktop(d)"
            >
              打开远程桌面
            </el-button>
            <el-dropdown trigger="click" @command="(a) => onPowerCmd(d, a)">
              <el-button size="small" :loading="poweringId === d.desktopId">电源 ▾</el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item v-for="a in actions" :key="a" :command="a">
                    {{ POWER_LABELS[a] }}
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </div>

        <div style="display: flex; align-items: center; gap: 14px; margin-top: 10px; flex-wrap: wrap">
          <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px">
            <el-switch v-model="d.keepaliveEnabled" size="small" /> 保活
          </label>
          <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px">
            <el-switch v-model="d.taskEnabled" size="small" /> 任务
          </label>
          <span style="display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px">
            间隔
            <el-input-number
              v-model="d.keepaliveInterval"
              :min="10"
              :max="604800"
              :step="30"
              size="small"
              style="width: 120px"
            />
            秒 <span class="form-hint">≈ {{ formatInterval(d.keepaliveInterval) }}</span>
          </span>
          <el-button size="small" type="primary" plain :loading="savingId === d.desktopId" @click="savePrefs(d)">
            保存配置
          </el-button>
          <span class="form-hint">最近脉冲：{{ fmtDateTime(d.lastPulseAt) }}</span>
        </div>
      </div>

      <div v-if="!items.length && !loading" class="grid-empty">暂无桌面数据</div>
    </div>
  </el-drawer>
</template>
