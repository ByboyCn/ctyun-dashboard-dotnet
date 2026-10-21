<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { ctyunApi } from '../api/endpoints'
import { errMsg } from '../utils/format'

const props = defineProps({
  modelValue: Boolean,
  card: { type: Object, required: true },
})
const emit = defineEmits(['update:modelValue', 'saved'])

const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const points = ref(0)
const tasks = ref([])
const rewards = ref([])
const loading = ref(false)
const redeeming = ref(false)
const desktops = computed(() => props.card.desktops || [])

const form = reactive({ prodId: '', times: 1, desktopId: '', pointType: 0 })

async function load() {
  loading.value = true
  const id = String(props.card.id || '')
  try {
    const [pts, rw] = await Promise.all([
      ctyunApi.points(id).catch(() => null),
      ctyunApi.rewards(id).catch(() => null),
    ])
    if (pts) {
      points.value = Number(pts.points) || 0
      tasks.value = pts.tasks || []
    }
    rewards.value = rw?.items || []
  } finally {
    loading.value = false
  }
}

watch(visible, (v) => {
  if (v) load()
})

const currentProd = computed(() => rewards.value.find((r) => r.prodId === form.prodId) || null)

async function redeem() {
  const p = currentProd.value
  if (!p) return ElMessage.warning('请选择要兑换的商品')
  redeeming.value = true
  try {
    await ctyunApi.redeem({
      accId: String(props.card.id || ''),
      prodId: p.prodId,
      prodName: p.prodName,
      costPoints: Number(p.costPoints) || 0,
      times: Number(form.times) || 1,
      desktopId: form.desktopId || '',
      pointType: Number(form.pointType) || 0,
    })
    ElMessage.success('兑换请求已提交')
    form.prodId = ''
    form.times = 1
    await load()
    emit('saved')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    redeeming.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="积分与兑换" width="640px" append-to-body>
    <div v-loading="loading">
      <div class="ac-stats" style="margin-bottom: 14px">
        <div class="stat">
          <span class="stat-num">{{ points }}</span>
          <span class="stat-label">当前积分</span>
        </div>
        <div class="stat">
          <span class="stat-num">{{ tasks.length }}</span>
          <span class="stat-label">任务数</span>
        </div>
      </div>

      <el-table :data="tasks" size="small" style="margin-bottom: 16px">
        <el-table-column prop="name" label="任务" min-width="120" />
        <el-table-column label="进度" min-width="100">
          <template #default="{ row }">{{ row.current }}/{{ row.total }}</template>
        </el-table-column>
        <el-table-column prop="points" label="积分" width="80" />
      </el-table>

      <el-form label-width="90px">
        <el-form-item label="兑换商品">
          <el-select v-model="form.prodId" placeholder="选择商品" style="width: 100%" filterable>
            <el-option
              v-for="r in rewards"
              :key="r.prodId"
              :label="`${r.prodName}（${r.costPoints} 积分）`"
              :value="r.prodId"
            />
          </el-select>
          <div v-if="currentProd?.description" class="form-hint">{{ currentProd.description }}</div>
        </el-form-item>
        <el-form-item label="兑换次数">
          <el-input-number v-model="form.times" :min="1" :max="99" />
        </el-form-item>
        <el-form-item label="目标桌面">
          <el-select v-model="form.desktopId" placeholder="可选，默认不指定" style="width: 100%" clearable>
            <el-option
              v-for="d in desktops"
              :key="d.desktopId"
              :label="d.name || d.desktopId"
              :value="d.desktopId"
            />
          </el-select>
        </el-form-item>
      </el-form>
    </div>
    <template #footer>
      <el-button @click="visible = false">关闭</el-button>
      <el-button type="primary" :loading="redeeming" :disabled="!form.prodId" @click="redeem">提交兑换</el-button>
    </template>
  </el-dialog>
</template>
