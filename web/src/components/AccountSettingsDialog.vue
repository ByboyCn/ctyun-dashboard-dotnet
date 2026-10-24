<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/endpoints'
import { errMsg, formatInterval } from '../utils/format'

const props = defineProps({
  modelValue: Boolean,
  card: { type: Object, required: true },
  platform: { type: String, required: true },
})
const emit = defineEmits(['update:modelValue', 'saved'])

const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const form = reactive({
  name: '',
  keepaliveEnabled: true,
  pulseInterval: 300,
  autoSign: true,
  autoAi: true,
  autoHang: true,
  autoRedeem: false,
  redeemStrategy: '',
  redeemDay: 1,
  redeemStepDays: 3,
  protocol: '',
})
const saving = ref(false)

watch(visible, (v) => {
  if (!v) return
  const c = props.card || {}
  Object.assign(form, {
    name: c.name || '',
    keepaliveEnabled: c.keepaliveEnabled !== false,
    pulseInterval: Number(c.pulseInterval) || 300,
    autoSign: !!c.autoSign,
    autoAi: !!c.autoAi,
    autoHang: !!c.autoHang,
    autoRedeem: !!c.autoRedeem,
    redeemStrategy: '',
    redeemDay: 1,
    redeemStepDays: 3,
    // 当前协议回显（AccountCard.protocol=23；ydpc 账号默认 ZTE）
    protocol: String(c.protocol || ''),
  })
})

async function save() {
  const payload = {
    id: String(props.card.id || ''),
    name: form.name.trim(),
    keepaliveEnabled: form.keepaliveEnabled,
    pulseInterval: Number(form.pulseInterval) || 300,
    autoSign: form.autoSign,
    autoAi: form.autoAi,
    autoHang: form.autoHang,
    autoRedeem: form.autoRedeem,
  }
  // 保活协议：仅 ydpc 账号；proto3 空字符串不序列化 = 不修改
  if (props.platform === 'ydpc' && form.protocol) {
    payload.protocol = form.protocol
  }
  // redeem 策略：仅在用户显式选择时下发（proto3 零值字段不会序列化）
  if (form.redeemStrategy) {
    payload.redeemStrategy = form.redeemStrategy
    payload.redeemDay = Number(form.redeemDay) || 1
    payload.redeemStepDays = Number(form.redeemStepDays) || 3
  }
  saving.value = true
  try {
    await api(props.platform).update(payload)
    ElMessage.success('账号设置已保存')
    visible.value = false
    emit('saved')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="账号设置" width="480px" append-to-body>
    <el-form label-width="110px">
      <el-form-item label="名称">
        <el-input v-model="form.name" placeholder="账号显示名称" maxlength="50" />
      </el-form-item>
      <el-form-item label="保活开关">
        <el-switch v-model="form.keepaliveEnabled" />
        <span class="form-hint" style="margin-left: 10px">关闭后状态徽章显示「保活暂停」</span>
      </el-form-item>
      <el-form-item label="脉冲间隔(秒)">
        <el-input-number v-model="form.pulseInterval" :min="10" :max="604800" :step="300" />
        <span class="form-hint" style="margin-left: 10px">10 ~ 604800 秒 ≈ {{ formatInterval(form.pulseInterval) }}</span>
      </el-form-item>
      <el-form-item v-if="platform === 'ydpc'" label="保活协议">
        <el-radio-group v-model="form.protocol">
          <el-radio value="ZTE">中兴 ZTE</el-radio>
          <el-radio value="SCG">深信服 SCG</el-radio>
        </el-radio-group>
        <div class="form-hint" style="width: 100%">
          {{ form.protocol === 'SCG' ? '深信服通道，适用于深信服类型桌面' : '中兴通道（默认）' }}
        </div>
      </el-form-item>
      <el-form-item label="自动打卡">
        <el-switch v-model="form.autoSign" />
      </el-form-item>
      <el-form-item label="自动AI任务">
        <el-switch v-model="form.autoAi" />
      </el-form-item>
      <el-form-item label="自动挂机">
        <el-switch v-model="form.autoHang" />
      </el-form-item>
      <el-form-item label="自动兑换">
        <el-switch v-model="form.autoRedeem" />
      </el-form-item>
      <el-form-item label="兑换策略">
        <el-select v-model="form.redeemStrategy" style="width: 100%">
          <el-option label="不修改（沿用全局设置）" value="" />
          <el-option label="每月（redeemDay 日）" value="monthly" />
          <el-option label="每日" value="daily" />
          <el-option label="间隔（stepDays 天）" value="interval" />
        </el-select>
      </el-form-item>
      <template v-if="form.redeemStrategy === 'monthly' || form.redeemStrategy === 'interval'">
        <el-form-item v-if="form.redeemStrategy === 'monthly'" label="兑换日">
          <el-input-number v-model="form.redeemDay" :min="1" :max="31" />
        </el-form-item>
        <el-form-item v-if="form.redeemStrategy === 'interval'" label="间隔天数">
          <el-input-number v-model="form.redeemStepDays" :min="1" :max="90" />
        </el-form-item>
      </template>
    </el-form>
    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>
