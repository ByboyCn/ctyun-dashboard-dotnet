<script setup>
import { computed } from 'vue'
import { STATUS_META } from '../utils/format'

const props = defineProps({
  status: { type: String, required: true },
  tip: { type: String, default: '' },
})

const meta = computed(() => STATUS_META[props.status] || STATUS_META.online)
</script>

<template>
  <span class="status-badge" :class="meta.cls" :title="tip">
    <i class="dot" />{{ meta.label }}
  </span>
</template>
