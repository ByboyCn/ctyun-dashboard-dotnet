<script setup>
import { computed } from 'vue'
import { taskPct } from '../utils/format'

const props = defineProps({
  label: { type: String, required: true },
  task: { type: Object, default: null },
})

const pct = computed(() => taskPct(props.task))
const done = computed(() => !!props.task && props.task.total > 0 && props.task.current >= props.task.total)
const text = computed(() => (props.task ? `${props.task.current || 0}/${props.task.total || 0}` : '—'))
</script>

<template>
  <div class="task-row" :class="{ 'is-idle': !task, 'is-done': done }">
    <span class="task-label">{{ label }}</span>
    <span class="task-bar"><i :style="{ width: pct + '%' }" /></span>
    <span class="task-text">{{ text }}</span>
  </div>
</template>
