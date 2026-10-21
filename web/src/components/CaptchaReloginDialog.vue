<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { ctyunApi } from '../api/endpoints'
import { errMsg } from '../utils/format'

// 验证码重新验证弹窗（天翼云 30060/30090 风控：服务端要求图形验证码登录）
const props = defineProps({
  modelValue: Boolean,
  card: { type: Object, required: true },
})
const emit = defineEmits(['update:modelValue', 'refreshed'])

const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const accId = computed(() => String(props.card?.id || ''))

const image = ref('')
const code = ref('')
const loading = ref(false)
const submitting = ref(false)
const errorText = ref('')

async function loadCaptcha(silent = false) {
  loading.value = true
  errorText.value = ''
  try {
    const d = await ctyunApi.reloginCaptcha(accId.value)
    image.value = d.image || ''
    if (!d.image && !silent) ElMessage.warning('后端未返回验证码图片')
  } catch (e) {
    if (!silent) ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

watch(visible, (v) => {
  if (v) {
    code.value = ''
    errorText.value = ''
    loadCaptcha()
  }
})

async function submit() {
  if (!code.value.trim()) return ElMessage.warning('请输入图形验证码')
  submitting.value = true
  try {
    const br = await ctyunApi.reloginCaptchaVerify(accId.value, code.value.trim())
    if (br.ok === false) {
      // 失败：展示 detail 并允许直接重试（图由后端在失败后变化，也可手动点图刷新）
      errorText.value = br.detail || '验证失败，请重试'
      code.value = ''
      return
    }
    ElMessage.success(`重新验证成功${br.detail ? `（${br.detail}）` : ''}`)
    visible.value = false
    emit('refreshed')
  } catch (e) {
    errorText.value = errMsg(e)
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <el-dialog v-model="visible" title="验证码重新验证" width="420px" append-to-body>
    <div class="form-hint" style="margin-bottom: 12px">
      账号：{{ card?.name || card?.userMasked || accId }} · 服务端要求图形验证码重新登录
    </div>

    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px">
      <div v-loading="loading" style="min-width: 132px; min-height: 44px; display: flex; align-items: center">
        <img
          v-if="image"
          :src="image"
          alt="验证码"
          title="看不清？点击刷新"
          style="height: 44px; border-radius: 6px; cursor: pointer; border: 1px solid var(--hairline)"
          @click="loadCaptcha()"
        />
        <el-button v-else size="small" :loading="loading" @click="loadCaptcha()">获取验证码</el-button>
      </div>
      <el-button size="small" text @click="loadCaptcha()">换一张</el-button>
    </div>

    <el-input
      v-model="code"
      placeholder="输入图中验证码"
      maxlength="10"
      @keyup.enter="submit"
    />
    <div v-if="errorText" class="form-hint" style="margin-top: 8px; color: var(--c-expired)">
      {{ errorText }}
    </div>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="submit">提交验证</el-button>
    </template>
  </el-dialog>
</template>
