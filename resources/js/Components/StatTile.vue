<script setup>
defineProps({
    label: { type: String, required: true },
    value: { type: [Number, String], required: true },
    tone: { type: String, default: 'normal' }, // normal | warn | alarm | idle
});

const toneClass = {
    normal: 'text-phosphor',
    warn: 'text-amber',
    alarm: 'text-alarm',
    idle: 'text-ink-dim',
};
</script>

<template>
    <div class="border border-grid bg-panel px-4 py-3">
        <div class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">{{ label }}</div>
        <div class="mt-1 text-2xl tabular-nums glow" :class="toneClass[tone]">{{ value }}</div>
    </div>
</template>
