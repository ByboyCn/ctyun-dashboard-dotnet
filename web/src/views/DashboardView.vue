<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import AccountCard from '../components/AccountCard.vue'
import AddAccountWizard from '../components/AddAccountWizard.vue'
import { api, PLATFORMS } from '../api/endpoints'
import { errMsg } from '../utils/format'

const router = useRouter()

// ===== 数据 =====
const platform = ref('ctyun')
const cards = ref([])
const loading = ref(false)
const wizardVisible = ref(false)

/** 进入设备墙（卡片双击 / 设备墙按钮） */
function enterWall(id) {
  router.push({ path: `/devices/${id}`, query: { platform: platform.value } })
}

async function load(silent = false) {
  if (!silent) loading.value = true
  try {
    const d = await api(platform.value).accounts()
    cards.value = d.items || []
  } catch (e) {
    if (!silent) ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

let pollTimer = null
onMounted(() => {
  load()
  pollTimer = setInterval(() => {
    if (document.visibilityState === 'visible') load(true)
  }, 30000)
})
onBeforeUnmount(() => clearInterval(pollTimer))
watch(platform, () => load())

// ===== 拖拽排序（原生 HTML5 DnD；顺序可含空位，存 localStorage） =====
const orderKey = computed(() => `ctydash.order.${platform.value}`)
const order = ref([])

function loadOrder() {
  try {
    const v = JSON.parse(localStorage.getItem(orderKey.value) || '[]')
    order.value = Array.isArray(v) ? v.map((x) => (x == null ? null : String(x))) : []
  } catch {
    order.value = []
  }
}
function saveOrder() {
  try {
    localStorage.setItem(orderKey.value, JSON.stringify(order.value))
  } catch {
    /* 存储失败忽略 */
  }
}
watch(orderKey, loadOrder, { immediate: true })

const idOf = (c) => String(c.id ?? '')
const byId = computed(() => {
  const m = new Map()
  for (const c of cards.value) m.set(idOf(c), c)
  return m
})

/** 渲染序列：order 中仍存在的 id（含 null 空位）+ 未入序账号追加尾部 */
const slots = computed(() => {
  const list = []
  const seen = new Set()
  for (const id of order.value) {
    if (id == null) {
      list.push(null)
      continue
    }
    if (byId.value.has(id)) {
      list.push(id)
      seen.add(id)
    }
  }
  for (const c of cards.value) {
    if (!seen.has(idOf(c))) list.push(idOf(c))
  }
  return list
})

function ensureAllOrdered(ord) {
  for (const c of cards.value) {
    const id = idOf(c)
    if (!ord.includes(id)) ord.push(id)
  }
}

function mutateOrder(fn) {
  const ord = [...order.value]
  ensureAllOrdered(ord)
  fn(ord)
  order.value = ord
  saveOrder()
}

function onDropCard(targetId) {
  const dragId = draggingId.value
  if (!dragId || dragId === targetId) return
  mutateOrder((ord) => {
    const from = ord.indexOf(dragId)
    const to = ord.indexOf(targetId)
    if (to < 0) return
    if (from < 0) {
      ord.splice(to, 0, dragId)
    } else {
      // 交换位置
      ;[ord[from], ord[to]] = [ord[to], ord[from]]
    }
  })
  clearDrag()
}

function onDropEmpty(slotIndex) {
  const dragId = draggingId.value
  if (!dragId) return
  mutateOrder((ord) => {
    const from = ord.indexOf(dragId)
    const target = ord[slotIndex]
    if (target != null && target !== dragId) return // 空位已被占（理论上不会）
    ord[slotIndex] = dragId
    if (from >= 0) ord[from] = null // 原位置留空位
  })
  clearDrag()
}

function onDropGrid() {
  const dragId = draggingId.value
  if (!dragId) return
  mutateOrder((ord) => {
    const from = ord.indexOf(dragId)
    if (from >= 0) ord.splice(from, 1)
    ord.push(dragId)
  })
  clearDrag()
}

function compact() {
  if (!cards.value.length) return
  order.value = slots.value.filter(Boolean)
  saveOrder()
  ElMessage.success('已整理：移除了全部空位')
}

// dragover 期间 dataTransfer 不可读，用响应式 ref 中转
const draggingId = ref('')
const overSlot = ref(-1)
const overCard = ref('')

function onCardDragStart(e, id) {
  draggingId.value = String(id)
  e.dataTransfer.effectAllowed = 'move'
  e.dataTransfer.setData('text/plain', String(id))
}

function onCardDragEnd() {
  clearDrag()
}

function clearDrag() {
  draggingId.value = ''
  overSlot.value = -1
  overCard.value = ''
}

function allowCardOver(e, id) {
  overCard.value = String(id)
}

function allowSlotOver(i) {
  overSlot.value = i
}
</script>

<template>
  <div>
    <div class="page-head">
      <div style="display: flex; align-items: center; gap: 14px">
        <el-radio-group v-model="platform" size="large">
          <el-radio-button v-for="p in PLATFORMS" :key="p.key" :value="p.key">
            {{ p.label }}
          </el-radio-button>
        </el-radio-group>
        <span class="muted">共 {{ cards.length }} 个账号 · 拖动排序（拖到空白处追加末尾，原位留空位）· 双击卡片进入设备墙</span>
      </div>
      <div class="tools">
        <el-button @click="compact">整理空位</el-button>
        <el-button @click="load()">刷新</el-button>
        <el-button type="primary" @click="wizardVisible = true">添加账号</el-button>
      </div>
    </div>

    <div
      v-loading="loading"
      class="card-grid"
      @dragover.prevent
      @drop.prevent="onDropGrid"
    >
      <template v-for="(id, i) in slots" :key="id ?? `slot-${i}`">
        <AccountCard
          v-if="id"
          :card="byId.get(id)"
          :platform="platform"
          draggable="true"
          :class="{ 'is-dragging': draggingId === id, 'is-dragover': overCard === id }"
          @dragstart="onCardDragStart($event, id)"
          @dragend="onCardDragEnd"
          @dragover.stop.prevent="allowCardOver($event, id)"
          @drop.stop.prevent="onDropCard(id)"
          @refresh="load(true)"
          @enter-wall="enterWall(id)"
        />
        <div
          v-else
          class="empty-slot"
          :class="{ 'is-dragover': overSlot === i }"
          @dragover.stop.prevent="allowSlotOver(i)"
          @dragleave="overSlot === i && (overSlot = -1)"
          @drop.stop.prevent="onDropEmpty(i)"
        >
          空位 · 可放置账号卡片
        </div>
      </template>

      <div v-if="!cards.length && !loading" class="grid-empty">
        还没有{{ platform === 'ydpc' ? '移动云' : '天翼云' }}账号，点击右上角「添加账号」开始
      </div>
    </div>

    <AddAccountWizard v-model="wizardVisible" :platform="platform" @saved="load(true)" />
  </div>
</template>
