<script setup>
import { nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { PLATFORMS, api, logApi } from '../api/endpoints'
import { errMsg, fmtShortTime } from '../utils/format'

// ===== 过滤条件（服务端过滤：与 /api/logs/recent 同参） =====
const filters = reactive({ scope: '', level: '', account: '' })
const levels = ['info', 'success', 'warning', 'error']

// 账号下拉：聚合两个平台的账号
const accountOptions = ref([])
async function loadAccounts() {
  const opts = []
  for (const p of PLATFORMS) {
    try {
      const d = await api(p.key).accounts()
      for (const c of d.items || []) {
        opts.push({ value: c.name || c.userMasked || String(c.id), label: `${c.name || c.userMasked || c.id}（${p.label}）` })
      }
    } catch {
      /* 单平台失败不影响另一个 */
    }
  }
  accountOptions.value = opts
}

// ===== 日志缓冲 =====
const MAX_LINES = 2000
const lines = ref([])
const autoScroll = ref(true)
const paused = ref(false)
const connected = ref(false)
const viewRef = ref(null)

let es = null
let debounceTimer = null

function pushLine(item) {
  lines.value.push({
    ts: item.ts || '',
    level: String(item.level || 'info').toLowerCase(),
    scope: item.scope || '',
    account: item.account || '',
    msg: item.msg ?? '',
  })
  if (lines.value.length > MAX_LINES) {
    lines.value.splice(0, lines.value.length - MAX_LINES)
  }
  if (autoScroll.value) scrollToBottom()
}

function scrollToBottom() {
  nextTick(() => {
    const el = viewRef.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

// ===== SSE =====
function startEs() {
  if (paused.value || es) return
  es = new EventSource(
    logApi.streamUrl({ limit: 200, level: filters.level, scope: filters.scope, account: filters.account }),
  )
  es.addEventListener('log', (e) => {
    try {
      pushLine(JSON.parse(e.data))
    } catch {
      /* 非 JSON 行忽略 */
    }
  })
  es.addEventListener('metrics', () => {
    /* 指标事件：日志页不消费 */
  })
  es.onopen = () => {
    connected.value = true
  }
  es.onerror = () => {
    // EventSource 断线自动重连
    connected.value = false
  }
}

function stopEs() {
  if (es) {
    es.close()
    es = null
  }
  connected.value = false
}

function loadRecent() {
  logApi
    .recent({ limit: 500, level: filters.level, scope: filters.scope, account: filters.account })
    .then((d) => {
      for (const it of d.items || []) pushLine(it)
    })
    .catch(() => {
      /* 历史拉取失败静默，SSE 仍在继续 */
    })
}

function applyFilters() {
  stopEs()
  lines.value = []
  loadRecent()
  startEs()
}

watch(
  filters,
  () => {
    clearTimeout(debounceTimer)
    debounceTimer = setTimeout(applyFilters, 400)
  },
  { deep: true },
)

watch(paused, (p) => {
  if (p) stopEs()
  else startEs()
})

function clearLines() {
  lines.value = []
}

onMounted(() => {
  loadAccounts()
  applyFilters()
})
onBeforeUnmount(() => {
  clearTimeout(debounceTimer)
  stopEs()
})
</script>

<template>
  <div>
    <div class="log-toolbar">
      <el-select v-model="filters.scope" placeholder="平台" style="width: 130px" clearable>
        <el-option label="全部平台" value="" />
        <el-option v-for="p in PLATFORMS" :key="p.key" :label="p.label" :value="p.key" />
      </el-select>
      <el-select v-model="filters.level" placeholder="级别" style="width: 130px" clearable>
        <el-option label="全部级别" value="" />
        <el-option v-for="l in levels" :key="l" :label="l" :value="l" />
      </el-select>
      <el-select
        v-model="filters.account"
        placeholder="账号（可输入过滤）"
        style="width: 220px"
        clearable
        filterable
        allow-create
        default-first-option
      >
        <el-option v-for="o in accountOptions" :key="o.value" :label="o.label" :value="o.value" />
      </el-select>

      <el-switch v-model="autoScroll" active-text="自动滚动" />
      <el-switch v-model="paused" active-text="暂停接收" />

      <span
        class="status-badge"
        :class="paused ? 'paused' : connected ? 'online' : 'waitScan'"
        style="margin-left: auto"
      >
        <i class="dot" />{{ paused ? '已暂停' : connected ? '实时连接中' : '连接/重连中' }}
      </span>
      <span class="muted">{{ lines.length }} 条</span>
      <el-button size="small" @click="clearLines">清屏</el-button>
      <el-button size="small" @click="applyFilters">重连</el-button>
    </div>

    <div ref="viewRef" class="log-view">
      <div v-for="(l, i) in lines" :key="i" class="log-line">
        <span class="t">{{ fmtShortTime(l.ts) }}</span>
        <span class="lv" :class="'lv-' + l.level">{{ l.level.toUpperCase().padEnd(7) }}</span>
        <span v-if="l.scope || l.account" class="s">[{{ l.scope }}{{ l.account ? '/' + l.account : '' }}]</span>
        <span>{{ l.msg }}</span>
      </div>
      <div v-if="!lines.length" class="grid-empty">暂无日志</div>
    </div>
  </div>
</template>
