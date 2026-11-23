<script setup>
import { computed, ref } from 'vue';

const props = defineProps({
    // [{ hour: '14:00', from, to, count: 812 }, ...] oldest first, zero-filled.
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

const bars = computed(() =>
    props.series.map((point, index) => {
        const height = (point.count / peak.value) * (BASELINE - TOP);

        return {
            ...point,
            index,
            x: index * (BAR + GAP),
            // A zero bar still gets a 1px stub so an empty hour reads as
            // "measured and quiet" rather than "no data".
            y: BASELINE - Math.max(height, point.count > 0 ? 2 : 1),
            height: Math.max(height, point.count > 0 ? 2 : 1),
        };
    })
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

                <g v-for="bar in bars" :key="bar.index">
                    <rect
                        :x="bar.x" :y="bar.y" :width="BAR" :height="bar.height"
                        rx="1"
                        :fill="bar.count > 0 ? 'var(--color-phosphor)' : 'var(--color-ink-faint)'"
                        :opacity="opacity(bar)"
                    />
                    <!-- Hit target spans the full column height, not just the bar. -->
                    <rect
                        :x="bar.x - GAP / 2" y="0" :width="BAR + GAP" height="100"
                        fill="transparent"
                        class="cursor-pointer outline-none"
                        role="button"
                        tabindex="0"
                        :aria-label="`${bar.hour}: ${bar.count} events. ${bar.from === selected ? 'Clear the hour filter.' : 'Filter the stream to this hour.'}`"
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
                :style="{ left: `${(hovered / series.length) * 100}%` }"
            >
                <span class="text-ink-dim">{{ series[hovered].hour }}</span>
                <span class="ml-2 tabular-nums text-phosphor">
                    {{ series[hovered].count.toLocaleString() }}
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
