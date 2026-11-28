<script setup>
import { computed, onUnmounted, ref, watch } from 'vue';
import { reducedMotion } from '../motion';

const props = defineProps({
    label: { type: String, required: true },
    // A number counts up to each new value; text ("3/3") just changes.
    value: { type: [Number, String], required: true },
    tone: { type: String, default: 'normal' }, // normal | warn | alarm | idle
});

// A live refresh that changes the number rolls it to the new value, and a
// rise flashes the tile's glow (an Open alerts tile flashes red).
const shown = ref(props.value);
const rose = ref(false);
let frame = null;
let flash = null;

watch(() => props.value, (to, from) => {
    cancelAnimationFrame(frame);
    if (typeof to !== 'number' || typeof from !== 'number' || reducedMotion()) {
        shown.value = to;
        return;
    }
    if (to > from) {
        rose.value = false;
        clearTimeout(flash);
        requestAnimationFrame(() => (rose.value = true));
        flash = setTimeout(() => (rose.value = false), 1300);
    }
    const begin = typeof shown.value === 'number' ? shown.value : from;
    const started = performance.now();
    const roll = (now) => {
        const t = Math.min(1, (now - started) / 600);
        shown.value = Math.round(begin + (to - begin) * (1 - (1 - t) ** 3));
        if (t < 1) frame = requestAnimationFrame(roll);
    };
    frame = requestAnimationFrame(roll);
});

onUnmounted(() => {
    cancelAnimationFrame(frame);
    clearTimeout(flash);
});

const text = computed(() => (typeof shown.value === 'number' ? shown.value.toLocaleString() : shown.value));

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
        <div class="mt-1 text-2xl tabular-nums glow" :class="[toneClass[tone], rose ? 'tick-up' : '']">{{ text }}</div>
    </div>
</template>
