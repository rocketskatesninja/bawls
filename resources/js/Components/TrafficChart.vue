<script setup>
import { computed, ref } from 'vue';

const props = defineProps({
    // [{ hour: '14:00', from, to, count: 812, kinds: { exploit, login, scan, page, firewall, other } }, ...]
    // oldest first, zero-filled.
    series: { type: Array, required: true },
    // The `from` of the hour the stream is filtered to, if any.
    selected: { type: String, default: null },
    // '24h' or '7d': 24 or 168 hourly bars.
    range: { type: String, default: '24h' },
});

// Clicking a bar filters the stream to that hour (Alt-click excludes it);
// the switch asks for the other range.
const emit = defineEmits(['pick', 'range']);
const ranges = [['24h', 'last 24h'], ['7d', 'last 7 days']];

function opacity(bar) {
    if (hovered.value !== null) return hovered.value === bar.index ? 0.9 : 0.35;
    if (props.selected) return props.selected === bar.from ? 1 : 0.35;
    return 0.9;
}

const hovered = ref(null);

const BAR = 8;
const GAP = 2;
const BASELINE = 88;
const TOP = 6;

const peak = computed(() => Math.max(1, ...props.series.map((p) => p.count)));

// Each bar stacks what its hour was made of: routine traffic (page views,
// firewall blocks) in the accent at the bottom, scans, logins and exploits
// on top, so trouble stands out at a glance. A trouble layer is never thinner
// than 2px, so one exploit in a busy hour still shows.
const LAYERS = [
    { key: 'routine', kinds: ['page', 'firewall', 'other'], color: 'var(--color-phosphor)', min: 0 },
    { key: 'scan', kinds: ['scan'], color: 'var(--color-amber)', min: 2 },
    { key: 'login', kinds: ['login'], color: 'var(--color-signal)', min: 2 },
    { key: 'exploit', kinds: ['exploit'], color: 'var(--color-alarm)', min: 2 },
];
const KIND_LABELS = [
    ['exploit', 'exploit', 'var(--color-alarm)'],
    ['login', 'login', 'var(--color-signal)'],
    ['scan', 'scan', 'var(--color-amber)'],
    ['page', 'page view', 'var(--color-phosphor)'],
    ['firewall', 'firewall', 'var(--color-phosphor)'],
    ['other', 'other', 'var(--color-phosphor)'],
];

function layersOf(point) {
    const kinds = point.kinds ?? { page: point.count };
    const height = Math.max((point.count / peak.value) * (BASELINE - TOP), 2);
    const sized = LAYERS.map((layer) => {
        const n = layer.kinds.reduce((sum, kind) => sum + (kinds[kind] ?? 0), 0);
        return { ...layer, n, height: n ? Math.max((n / point.count) * height, layer.min) : 0 };
    });
    // The routine layer gives up what the minimums took, so the bar keeps its height.
    const extra = sized.reduce((sum, layer) => sum + layer.height, 0) - height;
    if (extra > 0 && sized[0].height > extra) sized[0].height -= extra;
    let y = BASELINE;
    return sized.filter((layer) => layer.height > 0).map((layer) => ({ ...layer, y: (y -= layer.height) }));
}

/** The hour's kinds that happened, worst first: [[label, count, colour], ...]. */
function breakdown(point) {
    return KIND_LABELS.filter(([kind]) => point.kinds?.[kind]).map(([kind, label, color]) => [label, point.kinds[kind], color]);
}

const bars = computed(() =>
    props.series.map((point, index) => ({
        ...point,
        index,
        x: index * (BAR + GAP),
        layers: point.count > 0 ? layersOf(point) : [],
    }))
);

const width = computed(() => props.series.length * (BAR + GAP) - GAP);
const total = computed(() => props.series.reduce((sum, p) => sum + p.count, 0));
const peakPoint = computed(() => props.series.find((p) => p.count === peak.value));
</script>

<template>
    <div class="border border-grid bg-panel p-4">
        <div class="flex items-baseline justify-between">
            <div class="flex items-baseline gap-3">
                <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">
                    Events per hour · {{ ranges.find(([key]) => key === range)?.[1] }}
                </h2>
                <span class="flex gap-1" role="group" aria-label="Chart range">
                    <button
                        v-for="[key] in ranges"
                        :key="key"
                        type="button"
                        class="border px-1.5 text-[0.75rem] uppercase tracking-[0.1em]"
                        :class="key === range ? 'border-phosphor/60 text-phosphor' : 'border-edge text-ink-faint hover:text-phosphor'"
                        :aria-pressed="key === range"
                        @click="key !== range && emit('range', key)"
                    >{{ key }}</button>
                </span>
            </div>
            <span class="text-[0.8125rem] tabular-nums text-ink-faint">
                {{ total.toLocaleString() }} total · peak {{ peak.toLocaleString() }}
            </span>
        </div>

        <div class="relative mt-3">
            <svg
                :viewBox="`0 0 ${width} 100`"
                class="w-full"
                style="height: 7.5rem"
                preserveAspectRatio="none"
                role="img"
                :aria-label="`Events per hour over the last 24 hours. Peak ${peak} at ${peakPoint?.hour}.`"
            >
                <!-- Recessive baseline; no gridlines competing with the marks. -->
                <line :x1="0" :y1="BASELINE" :x2="width" :y2="BASELINE"
                      stroke="var(--color-grid)" stroke-width="1" vector-effect="non-scaling-stroke" />

                <g v-for="bar in bars" :key="bar.index" :opacity="opacity(bar)">
                    <rect
                        v-for="layer in bar.layers"
                        :key="layer.key"
                        :x="bar.x" :y="layer.y" :width="BAR" :height="layer.height"
                        :fill="layer.color"
                    />
                    <!-- A quiet hour still gets a 1px stub, so it reads as
                         "measured and quiet" rather than "no data". -->
                    <rect v-if="!bar.count" :x="bar.x" :y="BASELINE - 1" :width="BAR" height="1" fill="var(--color-ink-faint)" />
                    <!-- Hit target spans the full column height, not just the bar. -->
                    <rect
                        :x="bar.x - GAP / 2" y="0" :width="BAR + GAP" height="100"
                        fill="transparent"
                        class="cursor-pointer outline-none"
                        role="button"
                        tabindex="0"
                        :aria-label="`${bar.hour}: ${bar.count} events${breakdown(bar).length ? ` (${breakdown(bar).map(([label, n]) => `${n} ${label}`).join(', ')})` : ''}. ${bar.from === selected ? 'Clear the hour filter.' : 'Filter the stream to this hour.'}`"
                        @mouseenter="hovered = bar.index"
                        @mouseleave="hovered = null"
                        @focus="hovered = bar.index"
                        @blur="hovered = null"
                        @click="emit('pick', bar, $event.altKey)"
                        @keydown.enter.prevent="emit('pick', bar, $event.altKey)"
                    />
                </g>
            </svg>

            <div
                v-if="hovered !== null"
                class="pointer-events-none absolute -top-1 border border-edge bg-panel-lit px-2 py-1 text-[0.8125rem] whitespace-nowrap"
                :style="hovered / series.length > 0.55 ? { right: `${100 - ((hovered + 1) / series.length) * 100}%` } : { left: `${(hovered / series.length) * 100}%` }"
            >
                <span class="text-ink-dim">{{ series[hovered].hour }}</span>
                <span class="ml-2 tabular-nums text-phosphor">
                    {{ series[hovered].count.toLocaleString() }}
                </span>
                <span v-for="[label, n, color] in breakdown(series[hovered])" :key="label" class="ml-2 inline-flex items-center gap-1 tabular-nums text-ink-dim">
                    <span class="inline-block h-2 w-2" :style="{ background: color }" />{{ n.toLocaleString() }} {{ label }}
                </span>
                <span class="ml-2 text-ink-faint">{{ series[hovered].from === selected ? 'click to clear' : 'click to filter' }}</span>
            </div>
        </div>

        <div class="mt-1 flex justify-between text-[0.75rem] tabular-nums text-ink-faint">
            <span>{{ series[0]?.hour }}</span>
            <span>{{ series[Math.floor(series.length / 2)]?.hour }}</span>
            <span>now</span>
        </div>
    </div>
</template>
