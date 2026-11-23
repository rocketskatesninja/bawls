<script setup>
import { computed, onUnmounted, ref, watch } from 'vue';
import { COLS, LAND, LAT_BOTTOM, LAT_TOP, ROWS } from '../worldDots';
import { reducedMotion } from '../motion';

const props = defineProps({
    // [{ lat, lng, country, city, addresses, events, kind, last_seen }], worst first.
    points: { type: Array, required: true },
});

// Clicking a place filters the stream to its country (Alt-click excludes it).
const emit = defineEmits(['pick']);

// The land as one path of round dots: a zero-length line with round caps
// draws a dot. The grid is equirectangular, so a place is a straight scale.
const land = LAND.flatMap((row, y) => [...row].flatMap((cell, x) => (cell === '#' ? [`M${x + 0.5} ${y + 0.5}h0`] : []))).join('');

const COLOURS = {
    exploit: 'var(--color-alarm)',
    login: 'var(--color-signal)',
    scan: 'var(--color-amber)',
    page: 'var(--color-phosphor)',
    firewall: 'var(--color-phosphor-dim)',
    other: 'var(--color-ink-dim)',
};

const keyOf = (point) => `${point.lat},${point.lng}`;

// Drawn worst last, so a red dot is never hidden under a green one.
const dots = computed(() =>
    props.points
        .map((point) => ({
            ...point,
            key: keyOf(point),
            x: ((point.lng + 180) / 360) * COLS,
            y: Math.min(ROWS, Math.max(0, ((LAT_TOP - point.lat) / (LAT_TOP - LAT_BOTTOM)) * ROWS)),
            r: Math.min(2.2, 0.55 + Math.sqrt(point.events) * 0.12),
            colour: COLOURS[point.kind] ?? COLOURS.other,
        }))
        .reverse()
);

// A place with activity since the last refresh pings, like a radar contact.
// Nothing pings on page load, and nothing at all for reduced motion.
// The ping is one-shot: it's dropped once it has played (a refresh that
// brings identical points doesn't re-run this).
let lastSeen = null;
let settle = null;
const pinging = ref(new Set());
watch(() => props.points, (points) => {
    const seen = new Map(points.map((point) => [keyOf(point), point.last_seen]));
    pinging.value = lastSeen === null || reducedMotion()
        ? new Set()
        : new Set([...seen].filter(([key, at]) => (lastSeen.get(key) ?? '') < at).map(([key]) => key));
    lastSeen = seen;
    clearTimeout(settle);
    settle = setTimeout(() => (pinging.value = new Set()), 1800);
}, { immediate: true });
onUnmounted(() => clearTimeout(settle));

function describe(dot) {
    const place = [dot.city, dot.country].filter(Boolean).join(', ') || 'Somewhere';
    const who = `${dot.addresses} address${dot.addresses === 1 ? '' : 'es'}`;
    const hint = dot.country ? `\nClick to filter the stream to ${dot.country} · Alt-click to exclude` : '';
    return `${place} · ${who} · ${dot.events.toLocaleString()} events · worst: ${dot.kind}${hint}`;
}
</script>

<template>
    <div class="border border-grid bg-panel">
        <div class="flex items-baseline justify-between border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Attack map · 24h</h2>
            <span class="text-[0.75rem] tabular-nums text-ink-faint">{{ points.length }} place{{ points.length === 1 ? '' : 's' }}</span>
        </div>
        <div class="relative px-3 py-2">
            <!-- Mouse only: Top countries below filters the same way from the keyboard. -->
            <svg :viewBox="`0 0 ${COLS} ${ROWS}`" class="block w-full overflow-hidden" role="img" :aria-label="`Attack map: ${points.length} places in the last 24 hours`">
                <defs>
                    <linearGradient id="map-sweep-trail" x1="0" x2="1">
                        <stop offset="0" stop-color="var(--color-phosphor)" stop-opacity="0" />
                        <stop offset="1" stop-color="var(--color-phosphor)" stop-opacity="0.18" />
                    </linearGradient>
                </defs>
                <path :d="land" stroke="var(--color-grid)" stroke-width="0.55" stroke-linecap="round" fill="none" />
                <g class="map-sweep" aria-hidden="true">
                    <rect x="-14" y="0" width="14" :height="ROWS" fill="url(#map-sweep-trail)" />
                    <rect x="-0.3" y="0" width="0.3" :height="ROWS" fill="var(--color-phosphor)" opacity="0.45" />
                </g>
                <g v-for="dot in dots" :key="dot.key" class="map-place cursor-pointer" :data-kind="dot.kind" @click="emit('pick', dot, $event.altKey)">
                    <title>{{ describe(dot) }}</title>
                    <circle v-if="pinging.has(dot.key)" class="map-ping" :cx="dot.x" :cy="dot.y" :r="dot.r" fill="none" :stroke="dot.colour" stroke-width="0.35" />
                    <circle class="map-dot" :cx="dot.x" :cy="dot.y" :r="dot.r" :fill="dot.colour" />
                </g>
            </svg>
            <p v-if="!points.length" class="pointer-events-none absolute inset-0 flex items-center justify-center text-[0.75rem] text-ink-faint">
                No located traffic in the last 24 hours
            </p>
        </div>
    </div>
</template>
