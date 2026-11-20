<script setup>
import { computed, ref } from 'vue';

const props = defineProps({
    // [{ hour: '14:00', count: 812 }, ...] oldest first, zero-filled.
    series: { type: Array, required: true },
});

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
            <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">
                Events per hour · last 24h
            </h2>
            <span class="text-[13px] tabular-nums text-ink-faint">
                {{ total.toLocaleString() }} total · peak {{ peak.toLocaleString() }}
            </span>
        </div>

        <div class="relative mt-3">
            <svg
                :viewBox="`0 0 ${width} 100`"
                class="w-full"
                style="height: 120px"
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
                        :opacity="hovered === null || hovered === bar.index ? 0.9 : 0.35"
                    />
                    <!-- Hit target spans the full column height, not just the bar. -->
                    <rect
                        :x="bar.x - GAP / 2" y="0" :width="BAR + GAP" height="100"
                        fill="transparent"
                        @mouseenter="hovered = bar.index"
                        @mouseleave="hovered = null"
                    />
                </g>
            </svg>

            <div
                v-if="hovered !== null"
                class="pointer-events-none absolute -top-1 border border-edge bg-panel-lit px-2 py-1 text-[13px] whitespace-nowrap"
                :style="{ left: `${(hovered / series.length) * 100}%` }"
            >
                <span class="text-ink-dim">{{ series[hovered].hour }}</span>
                <span class="ml-2 tabular-nums text-phosphor">
                    {{ series[hovered].count.toLocaleString() }}
                </span>
            </div>
        </div>

        <div class="mt-1 flex justify-between text-[12px] tabular-nums text-ink-faint">
            <span>{{ series[0]?.hour }}</span>
            <span>{{ series[Math.floor(series.length / 2)]?.hour }}</span>
            <span>now</span>
        </div>
    </div>
</template>
