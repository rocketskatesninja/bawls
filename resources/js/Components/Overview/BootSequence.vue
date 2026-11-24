<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import BawlsMark from '../BawlsMark.vue';
import { reducedMotion } from '../../motion';
import { BOOT_FLAG, take } from '../../storage';

// Right after a sign-in (Login.vue leaves a flag), the console "boots": a
// few typed lines with the real numbers, about a second, then it lifts. Any
// key or click skips it. Never on a reload, and never for reduced motion.
const props = defineProps({ stats: { type: Object, required: true } });

const booting = ref(false);
const bootLeaving = ref(false);
const bootLines = computed(() => [
    { text: `linking sensors ........ ${props.stats.sensors_online}/${props.stats.sensors_total} online`, tone: props.stats.sensors_online === props.stats.sensors_total ? '' : 'text-amber' },
    { text: `events, last 24h ....... ${props.stats.events_24h.toLocaleString()}`, tone: '' },
    { text: `open alerts ............ ${props.stats.alerts_open}`, tone: props.stats.alerts_open ? 'text-alarm' : '' },
    { text: 'ready', tone: 'text-phosphor glow' },
]);
const bootShown = ref(0);
let bootTimers = [];

function endBoot() {
    bootTimers.forEach(clearTimeout);
    bootTimers = [];
    booting.value = false;
    window.removeEventListener('keydown', skipBoot, true);
    window.removeEventListener('pointerdown', skipBoot, true);
}

// The skipping key or click does nothing else (no shortcut, no typing): it
// is caught before any other handler and goes no further.
function skipBoot(event) {
    event.preventDefault();
    event.stopPropagation();
    endBoot();
}

onMounted(() => {
    if (take(BOOT_FLAG) !== '1' || reducedMotion()) return;
    booting.value = true;
    window.addEventListener('keydown', skipBoot, true);
    window.addEventListener('pointerdown', skipBoot, true);
    // Timings pair with the boot-* animations in app.css.
    bootLines.value.forEach((_, i) => bootTimers.push(setTimeout(() => (bootShown.value = i + 1), 120 + i * 170)));
    const done = 120 + bootLines.value.length * 170 + 350;
    bootTimers.push(setTimeout(() => (bootLeaving.value = true), done));
    bootTimers.push(setTimeout(endBoot, done + 300));
});
onUnmounted(endBoot);
</script>

<template>
    <div
        v-if="booting"
        class="boot fixed inset-0 z-50 flex items-center justify-center bg-void"
        :class="bootLeaving ? 'boot-out' : ''"
        aria-hidden="true"
    >
        <div class="w-[26rem] max-w-[90vw] text-[0.875rem] leading-relaxed">
            <div class="mb-3 flex items-center gap-3">
                <BawlsMark />
                <span class="tracking-[0.3em] text-phosphor glow">BAWLS</span>
                <span class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">honeypot console</span>
            </div>
            <div v-for="(line, i) in bootLines.slice(0, bootShown)" :key="i" class="boot-line text-ink-dim">
                <span class="text-ink-faint">&gt; </span><span :class="line.tone">{{ line.text }}</span><span v-if="i === bootShown - 1" class="boot-caret text-phosphor">▌</span>
            </div>
        </div>
    </div>
</template>
