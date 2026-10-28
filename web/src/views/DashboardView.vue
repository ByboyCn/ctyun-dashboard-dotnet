<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import AccountCard from '../components/AccountCard.vue'
import AddAccountWizard from '../components/AddAccountWizard.vue'
import { api, PLATFORMS } from '../api/endpoints'
import { errMsg } from '../utils/format'

const router = useRouter()
const PLATFORM_KEYS = PLATFORMS.map((p) => p.key)
const PLATFORM_LABEL = Object.fromEntries(PLATFORMS.map((p) => [p.key, p.label]))

// ===== 数据：两接口各自拉取，合并渲染（天翼在前、移动在后） =====
const cardsBy = reactive({ ctyun: [], ydpc: [] })
const loading = ref(false)
const wizardVisible = ref(false)
const wizardPlatform = ref('ctyun')

/** 进入设备墙（卡片双击 / 设备墙按钮） */
function enterWall(id, platform) {
  router.push({ path: `/devices/${id}`, query: { platform } })
}

async function load(silent = false) {
  if (!silent) loading.value = true
  const results = await Promise.allSettled([api('ctyun').accounts(), api('ydpc').accounts()])
  PLATFORM_KEYS.forEach((p, i) => {
    const r = results[i]
    if (r.status === 'fulfilled') cardsBy[p] = r.value.items || []
    else if (!silent) ElMessage.error(`${PLATFORM_LABEL[p]}：${errMsg(r.reason)}`)
  })
  if (!silent) loading.value = false
}

const counts = computed(() => ({
  ctyun: cardsBy.ctyun.length,
  ydpc: cardsBy.ydpc.length,
  total: cardsBy.ctyun.length + cardsBy.ydpc.length,
}))

let pollTimer = null
onMounted(() => {
  load()
  pollTimer = setInterval(() => {
    if (document.visibilityState === 'visible') load(true)
  }, 30000)
})
onBeforeUnmount(() => clearInterval(pollTimer))

// ===== 拖拽排序（各平台段内独立排序，顺序含空位，localStorage 持久化；跨平台拖动忽略） =====
const orderKey = (p) => `ctydash.order.${p}`
const orders = reactive({ ctyun: [], ydpc: [] })

function loadOrders() {
  for (const p of PLATFORM_KEYS) {
    try {
      const v = JSON.parse(localStorage.getItem(orderKey(p)) || '[]')
      orders[p] = Array.isArray(v) ? v.map((x) => (x == null ? null : String(x))) : []
    } catch {
      orders[p] = []
    }
  }
}
function saveOrder(p) {
  try {
    localStorage.setItem(orderKey(p), JSON.stringify(orders[p]))
  } catch {
    /* 存储失败忽略 */
  }
}
loadOrders()

const maps = computed(() => ({
  ctyun: new Map(cardsBy.ctyun.map((c) => [String(c.id ?? ''), c])),
  ydpc: new Map(cardsBy.ydpc.map((c) => [String(c.id ?? ''), c])),
}))

/** 单平台渲染序列：order 中仍存在的 id（含 null 空位，带 ordIndex）+ 未入序账号追加 */
function slotsOf(p) {
  const byId = maps.value[p]
  const ord = orders[p]
  const out = []
  const seen = new Set()
  for (let i = 0; i < ord.length; i++) {
    const id = ord[i]
    if (id == null) {
      out.push({ id: null, platform: p, ordIndex: i })
      continue
    }
    if (byId.has(id)) {
      out.push({ id, platform: p, ordIndex: i })
      seen.add(id)
    }
  }
  for (const c of cardsBy[p]) {
    const id = String(c.id ?? '')
    if (!seen.has(id)) out.push({ id, platform: p, ordIndex: -1 })
  }
  return out
}

/** 合并渲染序列：天翼段 + 移动段 */
const slots = computed(() => PLATFORM_KEYS.flatMap((p) => slotsOf(p)))

function ensureAllOrdered(p, ord) {
  for (const c of cardsBy[p]) {
    const id = String(c.id ?? '')
    if (!ord.includes(id)) ord.push(id)
  }
}

function mutateOrder(p, fn) {
  const ord = [...orders[p]]
  ensureAllOrdered(p, ord)
  fn(ord)
  orders[p] = ord
  saveOrder(p)
}

function onDropCard(slot) {
  if (!dragging.id || dragging.platform !== slot.platform || dragging.id === slot.id) return clearDrag()
  const p = slot.platform
  mutateOrder(p, (ord) => {
    const from = ord.indexOf(dragging.id)
    const to = ord.indexOf(slot.id)
    if (to < 0) return
    if (from < 0) ord.splice(to, 0, dragging.id)
    else {
      const t = ord[from]
      ord[from] = ord[to]
      ord[to] = t
    }
  })
  clearDrag()
}

function onDropEmpty(i) {
  const slot = slots.value[i]
  if (!dragging.id || !slot || dragging.platform !== slot.platform) return clearDrag()
  const p = slot.platform
  mutateOrder(p, (ord) => {
    if (slot.ordIndex < 0) {
      // 未入序账号追加到末尾
      const from = ord.indexOf(dragging.id)
      if (from >= 0) ord.splice(from, 1)
      ord.push(dragging.id)
      return
    }
    if (ord[slot.ordIndex] != null) return
    const from = ord.indexOf(dragging.id)
    ord[slot.ordIndex] = dragging.id
    if (from >= 0) ord[from] = null // 原位置留空位
  })
  clearDrag()
}

function onDropGrid() {
  if (!dragging.id) return
  const p = dragging.platform
  mutateOrder(p, (ord) => {
    const from = ord.indexOf(dragging.id)
    if (from >= 0) ord.splice(from, 1)
    ord.push(dragging.id)
  })
  clearDrag()
}

function compact() {
  if (!counts.value.total) return
  for (const p of PLATFORM_KEYS) {
    orders[p] = slotsOf(p)
      .filter((s) => s.id)
      .map((s) => s.id)
    saveOrder(p)
  }
  ElMessage.success('已整理：移除了全部空位')
}

// dragover 期间 dataTransfer 不可读，用响应式状态中转
const dragging = reactive({ id: '', platform: '' })
const overSlot = ref(-1)
const overCard = ref('')

function onCardDragStart(e, id, p) {
  dragging.id = String(id)
  dragging.platform = p
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', String(id))
}

function onCardDragEnd() {
  clearDrag()
}

function clearDrag() {
  dragging.id = ''
  dragging.platform = ''
  overSlot.value = -1
  overCard.value = ''
}

function allowCardOver(slot) {
  overCard.value = `${slot.platform}:${slot.id}`
}

function allowSlotOver(i) {
  overSlot.value = i
}
</script>

<template>
  <div>
    <div class="page-head">
      <div style="display: flex; align-items: center; gap: 14px; flex-wrap: wrap">
        <span style="font-size: 14.5px; font-weight: 600; color: var(--text-1)">
          共 {{ counts.total }} 个账号（天翼云 {{ counts.ctyun }} · 移动云 {{ counts.ydpc }}）
        </span>
        <span class="muted">拖动卡片可在同平台内排序（拖到空白处追加末尾，原位留空位）· 双击卡片进入设备墙</span>
      </div>
      <div class="tools">
        <el-button @click="compact">整理空位</el-button>
        <el-button @click="load()">刷新</el-button>
        <el-dropdown trigger="click" @command="(p) => { wizardPlatform = p; wizardVisible = true }">
          <el-button type="primary">添加账号 ▾</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item v-for="p in PLATFORMS" :key="p.key" :command="p.key">
                添加{{ p.label }}账号
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </div>

    <div v-loading="loading" class="card-grid" @dragover.prevent @drop.prevent="onDropGrid">
      <template v-for="(slot, i) in slots" :key="slot.id ?? `slot-${i}`">
        <AccountCard
          v-if="slot.id"
          :card="maps[slot.platform].get(slot.id)"
          :platform="slot.platform"
          draggable="true"
          :class="{ 'is-dragging': dragging.id === slot.id, 'is-dragover': overCard === `${slot.platform}:${slot.id}` }"
          @dragstart="onCardDragStart($event, slot.id, slot.platform)"
          @dragend="onCardDragEnd"
          @dragover.stop.prevent="allowCardOver(slot)"
          @drop.stop.prevent="onDropCard(slot)"
          @refresh="load(true)"
          @enter-wall="enterWall(slot.id, slot.platform)"
        />
        <div
          v-else
          class="empty-slot"
          :class="{ 'is-dragover': overSlot === i }"
          @dragover.stop.prevent="allowSlotOver(i)"
          @dragleave="overSlot === i && (overSlot = -1)"
          @drop.stop.prevent="onDropEmpty(i)"
        >
          空位（{{ PLATFORM_LABEL[slot.platform] }}）· 可放置账号卡片
        </div>
      </template>

      <div v-if="!counts.total && !loading" class="grid-empty">还没有任何账号，点击右上角「添加账号」开始</div>
    </div>

    <AddAccountWizard v-model="wizardVisible" :platform="wizardPlatform" @saved="load(true)" />
  </div>
</template>
