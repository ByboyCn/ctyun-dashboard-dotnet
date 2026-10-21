<script setup>
import { computed, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { ctyunApi } from '../api/endpoints'
import { errMsg } from '../utils/format'

// 短信验证设备绑定（天翼云 30060/30090 风控恢复通道）
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

const state = reactive({
  image: '',
  captchaCode: '',
  smsCode: '',
  loadingImage: false,
  sending: false,
  verifying: false,
  cooldown: 0,
  sent: false,
  errorText: '',
})
let cooldownTimer = null

async function loadCaptcha() {
  state.loadingImage = true
  state.errorText = ''
  try {
    const d = await ctyunApi.smsCaptcha(accId.value)
    state.image = d.image || ''
    if (!d.image) ElMessage.warning('后端未返回图形验证码')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    state.loadingImage = false
  }
}

function startCooldown() {
  state.cooldown = 60
  if (cooldownTimer) clearInterval(cooldownTimer)
  cooldownTimer = setInterval(() => {
    if (state.cooldown > 0) state.cooldown--
    else {
      clearInterval(cooldownTimer)
      cooldownTimer = null
    }
  }, 1000)
}

async function sendSms() {
  if (!state.captchaCode.trim()) return ElMessage.warning('请先输入图形验证码')
  state.sending = true
  state.errorText = ''
  try {
    const br = await ctyunApi.smsSend(accId.value, state.captchaCode.trim())
    if (br.ok === false) {
      state.errorText = br.detail || '发送失败，请重试'
      // 图形码大概率已失效，刷新并要求重输
      state.captchaCode = ''
      loadCaptcha()
      return
    }
    state.sent = true
    ElMessage.success('短信已发送至绑定手机')
    startCooldown()
  } catch (e) {
    state.errorText = errMsg(e)
  } finally {
    state.sending = false
  }
}

async function verify() {
  if (!state.sent) return ElMessage.warning('请先发送短信验证码')
  if (!state.smsCode.trim()) return ElMessage.warning('请输入短信验证码')
  state.verifying = true
  state.errorText = ''
  try {
    const br = await ctyunApi.smsVerify(accId.value, state.smsCode.trim())
    if (br.ok === false) {
      state.errorText = br.detail || '校验失败，请重试'
      state.smsCode = ''
      return
    }
    ElMessage.success(`设备绑定成功，风控解除${br.detail ? `（${br.detail}）` : ''}`)
    visible.value = false
    emit('refreshed')
  } catch (e) {
    state.errorText = errMsg(e)
  } finally {
    state.verifying = false
  }
}

watch(visible, (v) => {
  if (v) {
    Object.assign(state, {
      image: '',
      captchaCode: '',
      smsCode: '',
      cooldown: 0,
      sent: false,
      errorText: '',
    })
    loadCaptcha()
  }
})

onBeforeUnmount(() => {
  if (cooldownTimer) clearInterval(cooldownTimer)
})
</script>

<template>
  <el-dialog v-model="visible" title="短信验证设备" width="440px" append-to-body>
    <el-alert
      title="该账号被官方风控标记"
      type="warning"
      :closable="false"
      style="margin-bottom: 14px"
      description="完成短信验证设备绑定后，免密登录与任务中心立即恢复"
    />

    <div class="form-hint" style="margin-bottom: 12px">
      账号：{{ card?.name || card?.userMasked || accId }}
    </div>

    <!-- 第一步：图形码 + 发送短信 -->
    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px">
      <div v-loading="state.loadingImage" style="min-width: 132px; min-height: 44px; display: flex; align-items: center">
        <img
          v-if="state.image"
          :src="state.image"
          alt="图形验证码"
          title="看不清？点击刷新"
          style="height: 44px; border-radius: 6px; cursor: pointer; border: 1px solid var(--hairline)"
          @click="loadCaptcha"
        />
        <el-button v-else size="small" :loading="state.loadingImage" @click="loadCaptcha">获取图形码</el-button>
      </div>
      <el-input
        v-model="state.captchaCode"
        placeholder="图形验证码"
        maxlength="10"
        style="flex: 1"
        @keyup.enter="sendSms"
      />
    </div>

    <el-button
      style="width: 100%; margin-bottom: 14px"
      :loading="state.sending"
      :disabled="state.cooldown > 0"
      @click="sendSms"
    >
      {{ state.cooldown > 0 ? `${state.cooldown}s 后可重发` : '发送短信验证码' }}
    </el-button>

    <!-- 第二步：短信码 + 绑定 -->
    <div style="display: flex; gap: 10px">
      <el-input
        v-model="state.smsCode"
        :placeholder="state.sent ? '短信验证码' : '请先发送短信验证码'"
        maxlength="10"
        @keyup.enter="verify"
      />
      <el-button type="primary" :loading="state.verifying" @click="verify">绑定设备</el-button>
    </div>

    <div v-if="state.errorText" class="form-hint" style="margin-top: 10px; color: var(--c-expired)">
      {{ state.errorText }}
    </div>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
    </template>
  </el-dialog>
</template>
