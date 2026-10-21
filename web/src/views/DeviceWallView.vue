<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import StatusBadge from '../components/StatusBadge.vue'
import { api, FEATURES, POWER_LABELS, powerActionsFor, resolveDesktopOpenUrl } from '../api/endpoints'
import { errMsg, fmtDateTime, formatInterval, statusOf } from '../utils/format'

const route = useRoute()
const router = useRouter()

const accId = computed(() => String(route.params.accId || ''))
const platform = ref(route.query.platform === 'ydpc' ? 'ydpc' : 'ctyun')
const feat = computed(() => FEATURES[platform.value] || {})
const accApi = computed(() => api(platform.value))
// 账号可用电源动作（ydpc ecloud 额外有 poweron，按 AccountCard.platform 容错判断）
const tileActions = computed(() => powerActionsFor(platform.value, card.value))

// ===== 账号信息（名称/徽章） =====
const card = ref(null)
async function loadAccount() {
  try {
    const d = await accApi.value.accounts()
    card.value = (d.items || []).find((c) => String(c.id) === accId.value) || null
  } catch {
    card.value = null
  }
}
const accName = computed(() => card.value?.name || card.value?.userMasked || `账号 ${accId.value}`)

// ===== 桌面列表 =====
const PAGE_SIZE = 60
const items = ref([])
const loading = ref(false)
const search = ref('')
const statusFilter = ref('all') // all | running | other
const page = ref(1)
const autoRefresh = ref(false)

async function load(silent = false) {
  if (!silent) loading.value = true
  try {
    const d = await accApi.value.desktops(accId.value)
    items.value = d.items || []
  } catch (e) {
    if (!silent) ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  return items.value.filter((d) => {
    if (q && !`${d.name || ''}`.toLowerCase().includes(q) && !`${d.desktopId || ''}`.toLowerCase().includes(q)) {
      return false
    }
    const running = (d.useStatusText || '').includes('运行')
    if (statusFilter.value === 'running' && !running) return false
    if (statusFilter.value === 'other' && running) return false
    return true
  })
})

const pageItems = computed(() => filtered.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE))

watch([search, statusFilter], () => {
  page.value = 1
})

// ===== 自动刷新（30s 轮询 desktops） =====
let pollTimer = null
watch(autoRefresh, (v) => {
  clearInterval(pollTimer)
  if (v) pollTimer = setInterval(() => load(true), 30000)
})
onBeforeUnmount(() => clearInterval(pollTimer))

onMounted(() => {
  loadAccount()
  load()
})

// ===== 同步 =====
const syncing = ref(false)
async function doSync() {
  syncing.value = true
  try {
    await accApi.value.sync(accId.value)
    await Promise.all([load(), loadAccount()])
    ElMessage.success('已同步桌面列表与任务')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    syncing.value = false
  }
}

// ===== 勾选 =====
const selected = ref([])
function isSelected(d) {
  return selected.value.includes(d.desktopId)
}
function toggleSel(d, val) {
  const set = new Set(selected.value)
  if (val) set.add(d.desktopId)
  else set.delete(d.desktopId)
  selected.value = [...set]
}
const allPageSelected = computed(
  () => pageItems.value.length > 0 && pageItems.value.every((d) => selected.value.includes(d.desktopId)),
)
const somePageSelected = computed(() => pageItems.value.some((d) => selected.value.includes(d.desktopId)))
function toggleSelectPage(val) {
  const set = new Set(selected.value)
  for (const d of pageItems.value) {
    if (val) set.add(d.desktopId)
    else set.delete(d.desktopId)
  }
  selected.value = [...set]
}
function invertSelectPage() {
  const set = new Set(selected.value)
  for (const d of pageItems.value) {
    if (set.has(d.desktopId)) set.delete(d.desktopId)
    else set.add(d.desktopId)
  }
  selected.value = [...set]
}
function clearSelection() {
  selected.value = []
}

// ===== 批量配置（走 prefs/batch 端点，后端本地循环，desktopIds 空=全部桌面） =====
const batch = reactive({ running: false, done: 0, total: 0, fail: 0 })

async function runBatch(ids, label, fn) {
  batch.running = true
  batch.done = 0
  batch.total = ids.length
  batch.fail = 0
  for (const id of ids) {
    try {
      await fn(id)
    } catch {
      batch.fail++
    }
    batch.done++
  }
  batch.running = false
  if (batch.fail) {
    ElMessage.warning(`${label}完成：成功 ${ids.length - batch.fail} 台，失败 ${batch.fail} 台`)
  } else {
    ElMessage.success(`${label}完成（${ids.length} 台）`)
  }
  await load(true)
}

async function confirmBatch(text) {
  try {
    await ElMessageBox.confirm(text, '批量操作', {
      type: 'warning',
      confirmButtonText: '执行',
      cancelButtonText: '取消',
    })
    return true
  } catch {
    return false
  }
}

async function batchPower(action) {
  const ids = [...selected.value]
  if (!ids.length) return ElMessage.warning('请先勾选设备')
  if (!(await confirmBatch(`确定对已选 ${ids.length} 台设备逐台执行「${POWER_LABELS[action]}」吗？`))) return
  // 电源暂无批量端点，保持逐台下发 + 进度
  await runBatch(ids, `批量${POWER_LABELS[action]}`, (id) => accApi.value.power(accId.value, id, action))
}

/** 解析批量目标：已勾选 → 这些桌面；未勾选 → 确认后应用到全部（desktopIds 空） */
async function resolveBatchTargets(actionText) {
  const ids = [...selected.value]
  if (ids.length) {
    if (!(await confirmBatch(`确定对已选 ${ids.length} 台设备${actionText}吗？`))) return null
    return ids
  }
  if (!items.value.length) {
    ElMessage.warning('当前没有设备')
    return null
  }
  if (!(await confirmBatch(`未勾选设备：确定应用到该账号全部 ${items.value.length} 台吗？`))) return null
  return []
}

async function batchPref(key, val) {
  const what = key === 'keepaliveEnabled' ? '保活' : '任务'
  const desktopIds = await resolveBatchTargets(`${val ? '开启' : '关闭'}${what}`)
  if (desktopIds === null) return
  const payload = { id: accId.value, desktopIds }
  if (key === 'keepaliveEnabled') {
    payload.setKeepalive = true
    payload.keepaliveEnabled = val
  } else {
    payload.setTask = true
    payload.taskEnabled = val
  }
  try {
    const br = await accApi.value.prefsBatch(payload)
    ElMessage.success(`批量${what}${val ? '开启' : '关闭'}完成：更新 ${br.detail || '?'} 台`)
    await load(true)
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

// 批量保活间隔：预设 + 自定义秒数（0 = 清除单机覆盖，继承账号默认）
const INTERVAL_PRESETS = [
  { sec: 600, label: '10 分钟' },
  { sec: 1800, label: '30 分钟' },
  { sec: 3600, label: '1 小时' },
  { sec: 21600, label: '6 小时' },
  { sec: 43200, label: '12 小时' },
  { sec: 86400, label: '24 小时' },
]

async function onBatchInterval(cmd) {
  if (cmd === 'custom') {
    let val
    try {
      const { value } = await ElMessageBox.prompt(
        '输入保活间隔秒数（10 ~ 604800）；填 0 表示清除单机覆盖、继承账号默认',
        '自定义保活间隔',
        {
          inputValue: '21600',
          inputPattern: /^\d+$/,
          inputErrorMessage: '请输入非负整数秒数',
          confirmButtonText: '应用',
          cancelButtonText: '取消',
        },
      )
      val = Number(value)
    } catch {
      return
    }
    if (val !== 0 && !(val >= 10 && val <= 604800)) {
      return ElMessage.warning('超出范围：10 ~ 604800 秒（0 表示继承账号默认）')
    }
    return applyBatchInterval(val)
  }
  applyBatchInterval(Number(cmd))
}

async function applyBatchInterval(sec) {
  const desktopIds = await resolveBatchTargets(`保活间隔设为 ${formatInterval(sec)}`)
  if (desktopIds === null) return
  try {
    const br = await accApi.value.prefsBatch({
      id: accId.value,
      desktopIds,
      setInterval: true,
      keepaliveInterval: sec,
    })
    ElMessage.success(`保活间隔已设为 ${formatInterval(sec)}：更新 ${br.detail || '?'} 台`)
    await load(true)
  } catch (e) {
    ElMessage.error(errMsg(e))
  }
}

// ===== 单台操作 =====
const savingId = ref('')
async function saveTilePrefs(d, patch) {
  savingId.value = d.desktopId
  try {
    await accApi.value.prefs(accId.value, d.desktopId, {
      keepaliveEnabled: !!d.keepaliveEnabled,
      taskEnabled: !!d.taskEnabled,
      keepaliveInterval: Number(d.keepaliveInterval) || 30,
      ...patch,
    })
  } catch (e) {
    ElMessage.error(`「${d.name || d.desktopId}」配置保存失败：${errMsg(e)}`)
    await load(true)
  } finally {
    savingId.value = ''
  }
}

function onTileSwitch(d, key, val) {
  d[key] = val
  saveTilePrefs(d)
}

const poweringId = ref('')
async function tilePower(d, action) {
  if (action === 'shutdown' || action === 'reboot') {
    const ok = await confirmBatch(`确定对「${d.name || d.desktopId}」执行「${POWER_LABELS[action]}」吗？`)
    if (!ok) return
  }
  poweringId.value = d.desktopId
  try {
    await accApi.value.power(accId.value, d.desktopId, action)
    ElMessage.success(`已对「${d.name || d.desktopId}」下发「${POWER_LABELS[action]}」`)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    poweringId.value = ''
  }
}

// 打开远程桌面：免密直通优先（open 接口，首次可能现场登录需几秒），失败降级 connectUrl
const openingId = ref('')
const blockedId = ref('') // 后端明确拒绝（如 ydpc 暂不支持网页直通）后短暂禁用按钮
async function openDesktop(d) {
  if (blockedId.value === d.desktopId) return
  openingId.value = d.desktopId
  try {
    const r = await resolveDesktopOpenUrl(platform.value, accId.value, d)
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

function tileStatusCls(d) {
  const t = d.useStatusText || ''
  if (/运行|在线/.test(t)) return 'online'
  if (/错误|失败|异常/.test(t)) return 'expired'
  return 'paused'
}

// ===== raw_json 详情（官方原始字段：点击展开时才 parse，带按源串缓存） =====
const RAW_KEY_LABELS = {
  desktopId: '桌面ID',
  desktopName: '名称',
  deskname: '名称',
  useStatus: '状态码',
  useStatusText: '状态',
  flavorName: '规格',
  flavorId: '规格ID',
  imageName: '系统镜像',
  imageId: '镜像ID',
  desktopCode: '桌面编码',
  objType: '类型',
  cpu: 'CPU（核）',
  memory: '内存',
  expireTime: '有效期',
  expireDate: '有效期',
  createTime: '创建时间',
  ipAddr: 'IP 地址',
}
const rawCache = new Map() // desktopId -> { src, parsed }
const expandedIds = ref([])

function isDetailOpen(d) {
  return expandedIds.value.includes(d.desktopId)
}

function toggleDetail(d) {
  const set = new Set(expandedIds.value)
  if (set.has(d.desktopId)) set.delete(d.desktopId)
  else set.add(d.desktopId)
  expandedIds.value = [...set]
}

/** 返回 [key, value][]；解析失败返回 null（列表渲染期不调用，展开时才 parse） */
function rawEntries(d) {
  if (!d.rawJson) return []
  const hit = rawCache.get(d.desktopId)
  let parsed
  if (hit && hit.src === d.rawJson) {
    parsed = hit.parsed
  } else {
    try {
      parsed = JSON.parse(d.rawJson)
    } catch {
      parsed = undefined
    }
    rawCache.set(d.desktopId, { src: d.rawJson, parsed })
  }
  if (parsed === undefined) return null
  if (parsed === null) return [['(根值)', 'null']]
  if (Array.isArray(parsed)) return parsed.map((v, i) => [String(i), v])
  if (typeof parsed === 'object') return Object.entries(parsed)
  return [['(根值)', parsed]]
}

function displayVal(v) {
  if (v === null || v === undefined || v === '') return '-'
  // 嵌套对象/数组折叠为 JSON 字符串展示
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}
</script>

<template>
  <div>
    <!-- 顶栏 -->
    <div class="page-head">
      <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap">
        <el-button @click="router.push('/')">← 返回仪表盘</el-button>
        <span style="font-size: 16px; font-weight: 600; color: var(--text-1)">{{ accName }}</span>
        <StatusBadge
          :status="card ? statusOf(card) : 'online'"
          :tip="card?.statusText || card?.lastError || ''"
        />
        <span class="muted">共 {{ items.length }} 台设备</span>
      </div>
      <div class="tools">
        <el-input v-model="search" placeholder="按名称 / ID 过滤" clearable style="width: 200px" />
        <el-select v-model="statusFilter" style="width: 110px">
          <el-option label="全部状态" value="all" />
          <el-option label="运行中" value="running" />
          <el-option label="其他" value="other" />
        </el-select>
        <el-switch v-model="autoRefresh" active-text="30s 自动刷新" />
        <el-button :loading="syncing" @click="doSync">同步</el-button>
        <el-button :loading="loading" @click="load()">刷新</el-button>
      </div>
    </div>

    <!-- 批量栏 -->
    <div class="panel" style="margin-bottom: 14px; padding: 10px 14px">
      <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap">
        <el-checkbox
          :model-value="allPageSelected"
          :indeterminate="somePageSelected && !allPageSelected"
          @change="toggleSelectPage"
        >
          全选本页
        </el-checkbox>
        <el-button size="small" @click="invertSelectPage">反选本页</el-button>
        <el-button v-if="selected.length" size="small" text @click="clearSelection">清空选择</el-button>
        <span class="muted">已选 {{ selected.length }} 台</span>

        <el-divider direction="vertical" />

        <el-dropdown trigger="click" @command="batchPower">
          <el-button size="small" type="danger" plain :disabled="batch.running">批量电源 ▾</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="shutdown">批量关机</el-dropdown-item>
              <el-dropdown-item command="reboot">批量重启</el-dropdown-item>
              <el-dropdown-item command="poweron" divided>批量开机</el-dropdown-item>
              <el-dropdown-item command="awake">批量唤醒</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>

        <el-dropdown trigger="click" @command="(v) => batchPref('keepaliveEnabled', v)">
          <el-button size="small" :disabled="batch.running">批量保活 ▾</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item :command="true">批量开启保活</el-dropdown-item>
              <el-dropdown-item :command="false">批量关闭保活</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>

        <el-dropdown trigger="click" @command="(v) => batchPref('taskEnabled', v)">
          <el-button size="small" :disabled="batch.running">批量任务 ▾</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item :command="true">批量开启任务</el-dropdown-item>
              <el-dropdown-item :command="false">批量关闭任务</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>

        <el-tooltip content="一键归位：默认账号 6 小时（21600 秒）；未勾选时将应用到全部设备" placement="top">
          <el-dropdown trigger="click" @command="onBatchInterval">
            <el-button size="small" type="primary" plain>批量保活间隔 ▾</el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item v-for="p in INTERVAL_PRESETS" :key="p.sec" :command="p.sec">
                  {{ p.label }}（{{ formatInterval(p.sec) }}）
                </el-dropdown-item>
                <el-dropdown-item command="custom" divided>自定义秒数…</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </el-tooltip>

        <template v-if="batch.running">
          <el-progress
            :percentage="batch.total ? Math.round((batch.done / batch.total) * 100) : 0"
            style="flex: 1; min-width: 160px"
          />
          <span class="muted">{{ batch.done }}/{{ batch.total }}<template v-if="batch.fail"> · 失败 {{ batch.fail }}</template></span>
        </template>
      </div>
    </div>

    <!-- 设备网格 -->
    <div v-loading="loading" class="device-grid">
      <div v-for="d in pageItems" :key="d.desktopId" class="device-tile" :class="{ 'is-selected': isSelected(d) }">
        <div class="dt-head">
          <el-checkbox :model-value="isSelected(d)" @change="(v) => toggleSel(d, v)" />
          <span class="dt-name" :title="d.desktopId">{{ d.name || d.desktopId }}</span>
          <span class="status-badge" :class="tileStatusCls(d)">{{ d.useStatusText || '未知' }}</span>
        </div>
        <div class="dt-meta">
          <span>{{ d.spec || '规格未知' }}</span>
          <span>ID {{ d.desktopId }}</span>
          <span>脉冲 {{ fmtDateTime(d.lastPulseAt) }}</span>
        </div>
        <div class="dt-switches">
          <label class="dt-switch">
            <el-switch v-model="d.keepaliveEnabled" size="small" @change="(v) => onTileSwitch(d, 'keepaliveEnabled', v)" />
            保活
          </label>
          <label class="dt-switch">
            <el-switch v-model="d.taskEnabled" size="small" @change="(v) => onTileSwitch(d, 'taskEnabled', v)" />
            任务
          </label>
        </div>
        <div class="dt-actions">
          <el-dropdown trigger="click" @command="(a) => tilePower(d, a)">
            <el-button size="small" :loading="poweringId === d.desktopId">电源 ▾</el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item v-for="a in tileActions" :key="a" :command="a">
                  {{ POWER_LABELS[a] }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
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
          <el-button v-if="d.rawJson" size="small" text type="primary" @click="toggleDetail(d)">
            {{ isDetailOpen(d) ? '收起详情 ▴' : '详情 ▾' }}
          </el-button>
        </div>

        <!-- raw_json 全量键值（展开时才解析） -->
        <div v-if="d.rawJson && isDetailOpen(d)" class="dt-raw">
          <template v-if="rawEntries(d)">
            <div v-for="[k, v] in rawEntries(d)" :key="k" class="dt-raw-row">
              <span class="dt-raw-key">
                {{ RAW_KEY_LABELS[k] || k }}
                <i v-if="RAW_KEY_LABELS[k]" class="dt-raw-orig">{{ k }}</i>
              </span>
              <span class="dt-raw-val">{{ displayVal(v) }}</span>
            </div>
          </template>
          <div v-else class="dt-raw-row">
            <span class="dt-raw-val">原始 JSON 解析失败</span>
          </div>
        </div>
      </div>

      <div v-if="!loading && !filtered.length" class="grid-empty">
        {{ items.length ? '没有符合过滤条件的设备' : '暂无设备数据，点「同步」刷新' }}
      </div>
    </div>

    <!-- 分页 -->
    <div style="display: flex; justify-content: flex-end; margin-top: 14px">
      <el-pagination
        v-model:current-page="page"
        :page-size="PAGE_SIZE"
        :total="filtered.length"
        layout="total, prev, pager, next, jumper"
        background
      />
    </div>
  </div>
</template>

<style scoped>
.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(270px, 1fr));
  gap: 12px;
  min-height: 200px;
}

.device-tile {
  background: linear-gradient(180deg, var(--card-a), var(--card-b));
  border: 1px solid var(--card-border);
  border-radius: 12px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  transition: border-color 0.15s;
}

.device-tile:hover {
  border-color: var(--card-hover-border);
}

.device-tile.is-selected {
  border-color: var(--el-color-primary, #3b82f6);
  box-shadow: 0 0 0 1px var(--el-color-primary, #3b82f6);
}

.dt-head {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.dt-name {
  flex: 1;
  min-width: 0;
  font-weight: 600;
  font-size: 13.5px;
  color: var(--text-1);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.dt-meta {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 11.5px;
  color: var(--text-3);
}

.dt-switches {
  display: flex;
  gap: 16px;
}

.dt-switch {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--text-2);
  cursor: pointer;
}

.dt-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.dt-raw {
  max-height: 240px;
  overflow: auto;
  background: var(--stat-bg);
  border: 1px solid var(--stat-border);
  border-radius: 8px;
  padding: 6px 10px;
}

.dt-raw-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 2px 0;
  font-size: 12px;
}

.dt-raw-key {
  flex: none;
  min-width: 108px;
  color: var(--text-3);
}

.dt-raw-orig {
  font-style: normal;
  opacity: 0.6;
  font-size: 10.5px;
  margin-left: 4px;
}

.dt-raw-val {
  flex: 1;
  min-width: 0;
  word-break: break-all;
  white-space: pre-wrap;
  color: var(--text-2);
}
</style>
