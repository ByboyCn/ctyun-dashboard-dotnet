<script setup>
import { computed, nextTick, onBeforeUnmount, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import QRCode from 'qrcode'
import { api, ctyunApi, FEATURES, ydpcApi } from '../api/endpoints'
import { tryDecode } from '../api/proto'
import { errMsg } from '../utils/format'

const props = defineProps({
  modelValue: Boolean,
  platform: { type: String, required: true },
})
const emit = defineEmits(['update:modelValue', 'saved'])

const visible = computed({
  get: () => props.modelValue,
  set: (v) => emit('update:modelValue', v),
})

const feat = computed(() => FEATURES[props.platform] || {})
const mode = ref('password')

watch(visible, (v) => {
  if (v) reset()
})

watch(
  () => props.platform,
  () => {
    if (!feat.value.qr) mode.value = 'password'
  },
)

function reset() {
  Object.assign(pwdForm, { name: '', user: '', password: '', ydPlatform: 'soho', protocol: 'ZTE' })
  Object.assign(captcha, { need: false, image: '', key: '', code: '' })
  Object.assign(sms, {
    active: false,
    branch: '',
    accId: '',
    mobile: '',
    loginCode: '',
    code: '',
    isTemporary: false,
    hint: '',
    cooldown: 0,
  })
  if (smsTimer) {
    clearInterval(smsTimer)
    smsTimer = null
  }
  stopPolling()
  qr.qrId = ''
  qr.url = ''
  qr.status = ''
  mode.value = 'password'
}

// ===== 方式一：账密（+图形验证码） =====
const pwdForm = reactive({ name: '', user: '', password: '', ydPlatform: 'soho', protocol: 'ZTE' })
const captcha = reactive({ need: false, image: '', key: '', code: '' })
const submitting = ref(false)
const fetchingCaptcha = ref(false)

async function refreshCaptcha() {
  if (!feat.value.captcha) return
  if (!pwdForm.user) return ElMessage.warning('请先填写账号（手机号/用户名）')
  fetchingCaptcha.value = true
  try {
    const d = await ctyunApi.captcha(pwdForm.user)
    captcha.image = d.image || ''
    captcha.key = d.key || ''
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    fetchingCaptcha.value = false
  }
}

// ===== ecloud 短信验证分支（need_device_trust / need_two_factor / need_enhanced_sms） =====
const SMS_BRANCH_LABELS = {
  need_device_trust: '需要设备信任验证',
  need_two_factor: '需要二次验证（短信）',
  need_enhanced_sms: '需要增强短信验证',
  need_4a: '需要 4A 认证',
}
const sms = reactive({
  active: false,
  branch: '',
  accId: '',
  mobile: '',
  loginCode: '',
  code: '',
  isTemporary: false,
  hint: '',
  cooldown: 0,
})
let smsTimer = null

function enterSmsFlow(branchMsg) {
  Object.assign(sms, {
    active: true,
    branch: branchMsg.status || '',
    accId: branchMsg.accId || '',
    mobile: branchMsg.mobile || pwdForm.user.trim(),
    loginCode: branchMsg.loginCode || '',
    code: '',
    isTemporary: false,
    hint: branchMsg.error || '',
    cooldown: 0,
  })
  ElMessage.warning(`该登录需要短信验证：${SMS_BRANCH_LABELS[sms.branch] || sms.branch}`)
}

function startSmsCooldown() {
  sms.cooldown = 60
  if (smsTimer) clearInterval(smsTimer)
  smsTimer = setInterval(() => {
    if (sms.cooldown > 0) sms.cooldown--
    else {
      clearInterval(smsTimer)
      smsTimer = null
    }
  }, 1000)
}

const smsSending = ref(false)
async function sendSms() {
  if (!sms.accId) return ElMessage.error('缺少会话上下文（accId），请重新提交账密')
  smsSending.value = true
  try {
    const d = await ydpcApi.smsSend({
      accId: sms.accId,
      branch: sms.branch,
      mobile: sms.mobile.trim(),
      loginCode: sms.loginCode,
    })
    if (d.error) {
      sms.hint = d.error
      ElMessage.error(`发码失败：${d.error}`)
      return
    }
    sms.hint = d.mobile ? `验证码已发送至 ${d.mobile}` : '验证码已发送'
    ElMessage.success('短信验证码已发送')
    startSmsCooldown()
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    smsSending.value = false
  }
}

const smsVerifying = ref(false)
async function verifySms() {
  if (!sms.code.trim()) return ElMessage.warning('请输入短信验证码')
  smsVerifying.value = true
  try {
    const d = await ydpcApi.smsVerify({
      accId: sms.accId,
      branch: sms.branch,
      mobile: sms.mobile.trim(),
      code: sms.code.trim(),
      isTemporary: sms.isTemporary,
    })
    if (d.status === 'success') {
      ElMessage.success(`账号添加成功${d.accId ? `（accId=${d.accId}）` : ''}`)
      visible.value = false
      emit('saved')
    } else {
      ElMessage.error(d.error || `验证未通过（${d.status || '未知状态'}）`)
    }
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    smsVerifying.value = false
  }
}

const smsCountdownText = computed(() => (sms.cooldown > 0 ? `${sms.cooldown}s 后重发` : '重新发送'))

async function submitPassword() {
  if (!pwdForm.user || !pwdForm.password) return ElMessage.warning('请填写账号和密码')
  const payload = {
    name: pwdForm.name.trim(),
    user: pwdForm.user.trim(),
    password: pwdForm.password,
    // proto AddAccountReq.platform（字段15）：空=天翼云；ydpc-soho / ydpc-ecloud = 移动云
    platform: props.platform === 'ydpc' ? `ydpc-${pwdForm.ydPlatform}` : '',
    // proto AddAccountReq.protocol（字段16）：仅 ydpc 有意义（ZTE 默认 / SCG 深信服）；天翼云不带
    protocol: props.platform === 'ydpc' ? pwdForm.protocol : '',
  }
  if (captcha.need) {
    if (!captcha.code) return ElMessage.warning('请输入图形验证码')
    payload.captchaCode = captcha.code.trim()
    payload.captchaKey = captcha.key
  }
  submitting.value = true
  try {
    // Envelope.code 语义（后端契约，ydpc 已统一 BoolReply）：
    //   0 → 成功：BoolReply{ok=true,detail=accId}（兼容旧 YdpcLoginBranch.status=success）
    //   1 → 失败：BoolReply{ok=false,detail=人话错误}
    //   2 → 附加验证：YdpcLoginBranch(need_sms=true，ecloud 短信) 或 NeedCaptcha(soho/天翼 图形码)
    const env = await api(props.platform).addAccount(payload)
    const code = Number(env.code)
    if (code === 2) {
      // 先按登录分支解码（ecloud），再按图形验证码解码（soho / 天翼）
      const branchMsg = tryDecode(env.data, 'YdpcLoginBranch')
      if (branchMsg && (branchMsg.needSms || String(branchMsg.status || '').startsWith('need_'))) {
        enterSmsFlow(branchMsg)
        return
      }
      const nc = tryDecode(env.data, 'NeedCaptcha')
      if (nc && nc.need) {
        captcha.need = true
        captcha.image = nc.image || ''
        captcha.key = nc.key || ''
        captcha.code = ''
        ElMessage.warning('该登录需要图形验证码，请输入后重试')
        return
      }
      ElMessage.error(branchMsg?.error || '后端要求附加验证，但响应解码失败')
      return
    }
    if (code === 1) {
      // 失败：BoolReply.detail 为人话错误（兼容旧 YdpcLoginBranch.error 字段号碰撞）
      const br = tryDecode(env.data, 'BoolReply')
      ElMessage.error(br?.detail || env.msg || '添加失败')
      return
    }
    if (code !== 0) {
      ElMessage.error(env.msg || '添加失败')
      return
    }
    // code=0 成功：兼容旧后端 YdpcLoginBranch.status=success，统一按 BoolReply 处理
    const legacy = tryDecode(env.data, 'YdpcLoginBranch')
    if (legacy && legacy.status === 'success') {
      ElMessage.success(`账号添加成功${legacy.accId ? `（accId=${legacy.accId}）` : ''}`)
      visible.value = false
      emit('saved')
      return
    }
    const br = tryDecode(env.data, 'BoolReply')
    if (br && br.ok === false) {
      ElMessage.error(br.detail || '添加失败')
      return
    }
    ElMessage.success(`账号添加成功${br?.detail ? `（accId=${br.detail}）` : ''}`)
    visible.value = false
    emit('saved')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    submitting.value = false
  }
}

// ===== 方式二：扫码（仅天翼云） =====
const qr = reactive({ qrId: '', url: '', status: '' })
const qrCanvas = ref(null)
const qrLoading = ref(false)
const qrStarting = ref(false)
let pollTimer = null

const QR_STATUS_TEXT = {
  waiting: '等待扫码…',
  scanned: '已扫码，请在手机上确认',
  confirmed: '登录成功',
  expired: '二维码已过期',
}

async function startQr() {
  qrStarting.value = true
  try {
    stopPolling()
    const d = await ctyunApi.qrGenerate(pwdForm.name.trim())
    qr.qrId = d.qrId || ''
    qr.url = d.qrUrl || ''
    qr.status = 'waiting'
    await nextTick()
    await renderQr()
    pollTimer = setInterval(pollQr, 2000)
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    qrStarting.value = false
  }
}

async function renderQr() {
  if (!qrCanvas.value || !qr.url) return
  try {
    await QRCode.toCanvas(qrCanvas.value, qr.url, {
      width: 220,
      margin: 1,
      color: { dark: '#111827', light: '#ffffff' },
    })
  } catch (e) {
    ElMessage.error('二维码渲染失败：' + errMsg(e))
  }
}

async function pollQr() {
  if (!qr.qrId) return
  try {
    const d = await ctyunApi.qrStatus(qr.qrId)
    qr.status = d.status || 'waiting'
    if (qr.status === 'confirmed') {
      stopPolling()
      ElMessage.success(`扫码登录成功${d.accId ? `（accId=${d.accId}）` : ''}`)
      visible.value = false
      emit('saved')
    } else if (qr.status === 'expired') {
      stopPolling()
    }
  } catch {
    /* 轮询失败静默，下一轮重试 */
  }
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

onBeforeUnmount(() => {
  stopPolling()
  if (smsTimer) clearInterval(smsTimer)
})
</script>

<template>
  <el-dialog v-model="visible" :title="`添加账号 · ${platform === 'ydpc' ? '移动云' : '天翼云'}`" width="460px" append-to-body>
    <el-radio-group v-model="mode" style="margin-bottom: 18px">
      <el-radio-button value="password">账密登录</el-radio-button>
      <el-radio-button value="qr" :disabled="!feat.qr" :title="feat.qr ? '' : '移动云暂不支持扫码'">
        扫码登录
      </el-radio-button>
    </el-radio-group>

    <!-- 账密 -->
    <el-form v-if="mode === 'password' && !sms.active" label-width="92px" @submit.prevent="submitPassword">
      <el-form-item v-if="platform === 'ydpc'" label="移动云类型">
        <el-radio-group v-model="pwdForm.ydPlatform">
          <el-radio value="soho">SOHO（和家亲）</el-radio>
          <el-radio value="ecloud">ECLOUD（移动云电脑）</el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item v-if="platform === 'ydpc'" label="保活协议">
        <el-radio-group v-model="pwdForm.protocol">
          <el-radio value="ZTE">中兴 ZTE（默认）</el-radio>
          <el-radio value="SCG">深信服 SCG</el-radio>
        </el-radio-group>
        <div class="form-hint" style="width: 100%">
          {{ pwdForm.protocol === 'SCG' ? '深信服通道，适用于深信服类型桌面' : '中兴通道（默认）' }}
        </div>
      </el-form-item>
      <el-form-item label="备注名称">
        <el-input v-model="pwdForm.name" placeholder="可选，方便识别" maxlength="50" />
      </el-form-item>
      <el-form-item label="账号">
        <el-input v-model="pwdForm.user" placeholder="手机号 / 用户名" autocomplete="off" />
      </el-form-item>
      <el-form-item label="密码">
        <el-input v-model="pwdForm.password" type="password" show-password placeholder="密码" autocomplete="new-password" />
      </el-form-item>

      <el-form-item v-if="captcha.need" label="验证码">
        <div style="display: flex; align-items: center; gap: 8px; width: 100%">
          <el-input v-model="captcha.code" placeholder="图形验证码" style="flex: 1" @keyup.enter="submitPassword" />
          <img
            v-if="captcha.image"
            :src="captcha.image"
            alt="验证码"
            style="height: 32px; border-radius: 4px; cursor: pointer"
            title="点击刷新"
            @click="refreshCaptcha"
          />
          <el-button v-if="feat.captcha" size="small" :loading="fetchingCaptcha" @click="refreshCaptcha">刷新</el-button>
        </div>
      </el-form-item>
    </el-form>
    <div v-if="mode === 'password' && !sms.active" style="text-align: right">
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="submitting" @click="submitPassword">添加账号</el-button>
    </div>

    <!-- ecloud 短信验证分支 -->
    <div v-if="mode === 'password' && sms.active">
      <el-alert
        :title="SMS_BRANCH_LABELS[sms.branch] || sms.branch || '需要短信验证'"
        type="warning"
        :closable="false"
        style="margin-bottom: 14px"
        :description="sms.hint || '输入该账号收到的短信验证码完成登录'"
      />
      <el-form label-width="92px" @submit.prevent="verifySms">
        <el-form-item label="手机号">
          <el-input v-model="sms.mobile" placeholder="接收验证码的手机号" />
        </el-form-item>
        <el-form-item label="短信验证码">
          <div style="display: flex; gap: 8px; width: 100%">
            <el-input v-model="sms.code" placeholder="短信验证码" style="flex: 1" @keyup.enter="verifySms" />
            <el-button :loading="smsSending" :disabled="sms.cooldown > 0" @click="sendSms">
              {{ sms.cooldown > 0 ? smsCountdownText : '发送验证码' }}
            </el-button>
          </div>
        </el-form-item>
        <el-form-item v-if="sms.branch === 'need_device_trust'" label="设备信任">
          <el-checkbox v-model="sms.isTemporary">临时设备（本次信任，不长期保存）</el-checkbox>
        </el-form-item>
      </el-form>
      <div style="text-align: right">
        <el-button @click="Object.assign(sms, { active: false, code: '' })">返回修改</el-button>
        <el-button type="primary" :loading="smsVerifying" @click="verifySms">验证并添加账号</el-button>
      </div>
    </div>

    <!-- 扫码 -->
    <div v-else style="display: flex; flex-direction: column; align-items: center; gap: 12px; padding-bottom: 8px">
      <div v-if="!qr.url" class="empty-slot" style="width: 220px; height: 220px">
        <el-button type="primary" :loading="qrStarting" @click="startQr">生成登录二维码</el-button>
      </div>
      <template v-else>
        <div style="padding: 10px; background: #fff; border-radius: 10px">
          <canvas ref="qrCanvas" />
        </div>
        <div v-if="qr.status" class="form-hint" :style="{ color: qr.status === 'confirmed' ? 'var(--c-online)' : qr.status === 'expired' ? 'var(--c-expired)' : 'var(--text-3)' }">
          {{ QR_STATUS_TEXT[qr.status] || qr.status }}
        </div>
        <el-button size="small" :loading="qrStarting" @click="startQr">
          {{ qr.status === 'expired' ? '重新生成' : '刷新二维码' }}
        </el-button>
      </template>
      <div class="form-hint">备注名称：{{ pwdForm.name || '（未填写）' }}</div>
    </div>
  </el-dialog>
</template>
