<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { settingsApi, systemApi } from '../api/endpoints'
import { errMsg, fmtDateTime, fmtUptime, formatInterval } from '../utils/format'

// SettingsMsg 全量扁平结构（proto 默认值兜底）
function defaults() {
  return {
    pulseIntervalSeconds: 300,
    keepAliveSeconds: 60,
    executeTime: [],
    signCron: '',
    aiCron: '',
    hangCron: '',
    redeemCron: '',
    redeemMode: 'monthly',
    redeemModeDay: 1,
    redeemModeStepDays: 3,
    notifyOnErrorOnly: true,
    notifyChannels: [],
    title: '',
    subtitle: '',
    hookUrl: '',
  }
}

const form = reactive(defaults())
const loading = ref(false)
const saving = ref(false)
const sysInfo = ref(null)

const CHANNEL_TYPES = ['feishu', 'dingtalk', 'wecom', 'telegram', 'webhook']

function addChannel() {
  form.notifyChannels.push({ type: 'feishu', url: '', secret: '', accScope: '' })
}
function removeChannel(i) {
  form.notifyChannels.splice(i, 1)
}
function addTime() {
  form.executeTime.push('08:00')
}
function removeTime(i) {
  form.executeTime.splice(i, 1)
}

async function load() {
  loading.value = true
  try {
    const d = await settingsApi.get()
    Object.assign(form, defaults(), d || {})
    if (!Array.isArray(form.executeTime)) form.executeTime = []
    if (!Array.isArray(form.notifyChannels)) form.notifyChannels = []
    if (!form.redeemMode) form.redeemMode = 'monthly'
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    await settingsApi.save({ ...form })
    ElMessage.success('设置已保存')
  } catch (e) {
    ElMessage.error(errMsg(e))
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  load()
  systemApi
    .info()
    .then((d) => (sysInfo.value = d))
    .catch(() => {})
})
</script>

<template>
  <div v-loading="loading">
    <div class="page-head">
      <span class="muted">调度 / 兑换 / 通知 / 品牌设置（仅管理员）</span>
      <el-button type="primary" :loading="saving" @click="save">保存全部设置</el-button>
    </div>

    <!-- 调度 -->
    <div class="panel">
      <h4 style="margin: 0 0 14px">调度</h4>
      <div style="display: flex; gap: 24px; flex-wrap: wrap">
        <div>
          <div class="form-hint" style="margin-bottom: 6px">脉冲间隔（秒 · 10 ~ 604800，即 10 秒 ~ 7 天）</div>
          <el-input-number v-model="form.pulseIntervalSeconds" :min="10" :max="604800" :step="300" />
          <div class="form-hint" style="margin-top: 4px">≈ {{ formatInterval(form.pulseIntervalSeconds) }}</div>
        </div>
        <div>
          <div class="form-hint" style="margin-bottom: 6px">保活间隔（秒）</div>
          <el-input-number v-model="form.keepAliveSeconds" :min="10" :max="86400" :step="10" />
        </div>
      </div>

      <div style="margin-top: 16px">
        <div class="form-hint" style="margin-bottom: 6px">
          每日执行时间点（到点执行 打卡/AI/挂机 流程）
          <el-button size="small" style="margin-left: 8px" @click="addTime">+ 添加时间点</el-button>
        </div>
        <div style="display: flex; gap: 10px; flex-wrap: wrap">
          <span v-for="(t, i) in form.executeTime" :key="i" style="display: inline-flex; align-items: center; gap: 4px">
            <el-time-picker v-model="form.executeTime[i]" format="HH:mm" value-format="HH:mm" placeholder="HH:mm" />
            <el-button size="small" text type="danger" @click="removeTime(i)">删除</el-button>
          </span>
          <span v-if="!form.executeTime.length" class="muted">未配置（将仅按 cron 执行）</span>
        </div>
      </div>

      <div style="display: flex; gap: 16px; margin-top: 16px; flex-wrap: wrap">
        <div v-for="f in [
            { k: 'signCron', label: '打卡 cron' },
            { k: 'aiCron', label: 'AI 任务 cron' },
            { k: 'hangCron', label: '挂机 cron' },
            { k: 'redeemCron', label: '兑换 cron' },
          ]"
          :key="f.k"
          style="min-width: 220px; flex: 1"
        >
          <div class="form-hint" style="margin-bottom: 6px">{{ f.label }}</div>
          <el-input v-model="form[f.k]" placeholder="如 0 9 * * *，留空=不启用" />
        </div>
      </div>
    </div>

    <!-- 兑换策略 -->
    <div class="panel section-gap">
      <h4 style="margin: 0 0 14px">兑换策略</h4>
      <el-radio-group v-model="form.redeemMode">
        <el-radio-button value="monthly">每月</el-radio-button>
        <el-radio-button value="daily">每日</el-radio-button>
        <el-radio-button value="interval">间隔</el-radio-button>
      </el-radio-group>
      <div style="display: flex; gap: 24px; margin-top: 12px">
        <div v-if="form.redeemMode === 'monthly'">
          <div class="form-hint" style="margin-bottom: 6px">每月兑换日</div>
          <el-input-number v-model="form.redeemModeDay" :min="1" :max="31" />
        </div>
        <div v-if="form.redeemMode === 'interval'">
          <div class="form-hint" style="margin-bottom: 6px">间隔天数</div>
          <el-input-number v-model="form.redeemModeStepDays" :min="1" :max="90" />
        </div>
        <div v-if="form.redeemMode === 'daily'" class="form-hint">每日自动兑换，无需额外参数。</div>
      </div>
    </div>

    <!-- 通知 -->
    <div class="panel section-gap">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px">
        <h4 style="margin: 0">通知渠道</h4>
        <div style="display: flex; align-items: center; gap: 10px">
          <span class="form-hint">仅错误时通知</span>
          <el-switch v-model="form.notifyOnErrorOnly" />
          <el-button size="small" type="primary" plain @click="addChannel">+ 添加渠道</el-button>
        </div>
      </div>

      <div v-for="(ch, i) in form.notifyChannels" :key="i" class="channel-row">
        <el-select v-model="ch.type" style="width: 140px" filterable allow-create default-first-option placeholder="类型">
          <el-option v-for="t in CHANNEL_TYPES" :key="t" :label="t" :value="t" />
        </el-select>
        <el-input v-model="ch.url" placeholder="Webhook 地址" style="flex: 1; min-width: 240px" />
        <el-input v-model="ch.secret" placeholder="签名密钥（可选）" style="width: 200px" show-password />
        <el-input v-model="ch.accScope" placeholder="账号范围：留空=全部，多个用逗号分隔" style="width: 240px" />
        <el-button size="small" text type="danger" @click="removeChannel(i)">删除</el-button>
      </div>
      <div v-if="!form.notifyChannels.length" class="form-hint">暂未配置通知渠道</div>
    </div>

    <!-- 保活完成回调 Hook -->
    <div class="panel section-gap">
      <h4 style="margin: 0 0 14px">保活完成回调 Hook</h4>
      <el-input
        v-model="form.hookUrl"
        placeholder="https://your.domain/hook/keepalive"
        clearable
        maxlength="300"
      />
      <div class="form-hint" style="margin-top: 8px">
        每次保活脉冲结束后（无论成败）POST 该地址；query 与 JSON body 均携带
        desktopCode、desktopId、desktopName、account、status(success/failed)、heldSeconds、reason、error、ts。留空禁用。
      </div>
    </div>

    <!-- 品牌 -->
    <div class="panel section-gap">
      <h4 style="margin: 0 0 14px">品牌</h4>
      <div style="display: flex; gap: 16px; flex-wrap: wrap">
        <div style="min-width: 240px; flex: 1">
          <div class="form-hint" style="margin-bottom: 6px">标题</div>
          <el-input v-model="form.title" placeholder="控制台标题" maxlength="40" />
        </div>
        <div style="min-width: 240px; flex: 1">
          <div class="form-hint" style="margin-bottom: 6px">副标题</div>
          <el-input v-model="form.subtitle" placeholder="副标题 / Slogan" maxlength="80" />
        </div>
      </div>
    </div>

    <!-- 系统信息 -->
    <div class="panel section-gap">
      <h4 style="margin: 0 0 10px">系统信息</h4>
      <div v-if="sysInfo" class="form-hint" style="font-size: 13px">
        版本 v{{ sysInfo.version }} · 运行时 {{ sysInfo.runtime }} · 启动于 {{ fmtDateTime(sysInfo.startedAt) }} ·
        已运行 {{ fmtUptime(sysInfo.uptimeSec) }} · 账号数 {{ sysInfo.accountCount }}
      </div>
      <div v-else class="form-hint">后端未连接</div>
    </div>
  </div>
</template>
