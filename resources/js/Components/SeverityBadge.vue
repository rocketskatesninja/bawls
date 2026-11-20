<script setup>
import { computed } from 'vue';

const props = defineProps({
    severity: { type: Number, required: true },
});

// Severity is always shown as colour AND text. Amber and green sit close
// together under deuteranopia, so the word is what actually carries the
// meaning; the colour only reinforces it.
const levels = {
    1: { label: 'INFO', class: 'text-signal border-signal/40' },
    2: { label: 'LOW', class: 'text-signal border-signal/40' },
    3: { label: 'MEDIUM', class: 'text-amber border-amber/40' },
    4: { label: 'HIGH', class: 'text-alarm border-alarm/40' },
    5: { label: 'CRITICAL', class: 'text-alarm border-alarm/60' },
};

const level = computed(() => levels[props.severity] ?? levels[1]);
</script>

<template>
    <span
        class="inline-block border px-1.5 py-px text-[12px] font-bold tracking-[0.15em]"
        :class="level.class"
    >{{ level.label }}</span>
</template>
