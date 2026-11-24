<script setup>
import { computed } from 'vue';
import { hint } from '../stream';

// Anything you can click to add to the stream's filter (Alt-click excludes
// it instead). The tooltip always says what the click will do; `lines` go
// above that (the full text of a truncated label, what a signature means).
// Classes pass through to the button.
const props = defineProps({
    condition: { type: String, required: true }, // filter text, e.g. "src == 203.0.113.9"
    lines: { type: Array, default: () => [] },
});
const emit = defineEmits(['filter']); // (condition, exclude)

const title = computed(() => [...props.lines, hint(props.condition)].filter(Boolean).join('\n'));
</script>

<template>
    <!-- .stop: inside a stream row, the click must not also select the row. -->
    <button type="button" :title="title" @click.stop="emit('filter', condition, $event.altKey)"><slot /></button>
</template>
