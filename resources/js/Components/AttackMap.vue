<script setup>
import { computed, onUnmounted, ref, watch } from 'vue';
import { COLS, LAT_BOTTOM, LAT_TOP, LEVEL, ROWS } from '../worldDots';
import { reducedMotion } from '../motion';

const props = defineProps({
    // [{ lat, lng, country, city, addresses, events, kind, last_seen }], worst first.
    points: { type: Array, required: true },
});

// Clicking a place filters the stream to its country (Alt-click excludes it).
const emit = defineEmits(['pick']);

// The land as one path of round dots: a zero-length line with round caps
// draws a dot. The grid is equirectangular, so a place is a straight scale.
// It comes at four levels of detail (2.5° down to 0.3125°): each doubling of
// zoom uses a grid twice as fine with dots half the size, so the dots stay
// small on screen and coastlines sharpen as you zoom in. Only the dots in
// view are drawn, and the finer grids load the first time they're needed.
const parseLevel = (level) => ({
    ...level,
    runs: level.runs.split('|').map((row) => (row ? row.split(',').map((run) => run.split(':').map((n) => parseInt(n, 36))) : [])),
});
const levels = ref([parseLevel(LEVEL)]);
const FINER = [null, () => import('../worldDots1.js'), () => import('../worldDots2.js'), () => import('../worldDots3.js')];

const COLOURS = {
    exploit: 'var(--color-alarm)',
    login: 'var(--color-signal)',
    scan: 'var(--color-amber)',
    page: 'var(--color-phosphor)',
    firewall: 'var(--color-phosphor-dim)',
    other: 'var(--color-ink-dim)',
};

const keyOf = (point) => `${point.lat},${point.lng}`;

// --- zoom and pan ---------------------------------------------------------
// The view is the SVG's viewBox, in grid units: the whole world at 1x, an
// eighth of its width at 8x, always the world's shape and never past its
// edges. The wheel zooms around the pointer, a drag pans, a double-click
// zooms in, and the buttons (or + − 0 and the arrows, once the map has
// focus) do the same from the corner.
const MAX_ZOOM = 8;
const svg = ref(null);
const view = ref({ x: 0, y: 0, w: COLS, h: ROWS });
const zoom = computed(() => COLS / view.value.w);

function clamp(next) {
    const w = Math.min(COLS, Math.max(COLS / MAX_ZOOM, next.w));
    const h = (w * ROWS) / COLS;
    return { w, h, x: Math.min(COLS - w, Math.max(0, next.x)), y: Math.min(ROWS - h, Math.max(0, next.y)) };
}

/** The view zoomed by `factor` (>1 in), keeping the grid point (cx, cy) where it is. */
function zoomedView(factor, cx, cy) {
    const v = view.value;
    const w = v.w / factor;
    return clamp({ w, x: cx - (cx - v.x) * (w / v.w), y: cy - (cy - v.y) * (w / v.w) });
}

// Buttons and keys glide; the wheel and a drag follow the hand directly.
let glide = null;
function glideTo(target) {
    cancelAnimationFrame(glide);
    if (reducedMotion()) {
        view.value = target;
        return;
    }
    const from = { ...view.value };
    const started = performance.now();
    const step = (now) => {
        const t = Math.min(1, (now - started) / 180);
        const e = 1 - (1 - t) ** 3;
        view.value = Object.fromEntries(Object.keys(target).map((k) => [k, from[k] + (target[k] - from[k]) * e]));
        if (t < 1) glide = requestAnimationFrame(step);
    };
    glide = requestAnimationFrame(step);
}
onUnmounted(() => cancelAnimationFrame(glide));

const centre = () => ({ x: view.value.x + view.value.w / 2, y: view.value.y + view.value.h / 2 });
const zoomIn = () => glideTo(zoomedView(2, centre().x, centre().y));
const zoomOut = () => glideTo(zoomedView(0.5, centre().x, centre().y));
const reset = () => glideTo({ x: 0, y: 0, w: COLS, h: ROWS });
const pan = (dx, dy) => glideTo(clamp({ ...view.value, x: view.value.x + dx * view.value.w, y: view.value.y + dy * view.value.h }));

/** A pointer event's position in grid units. */
function gridPoint(event) {
    const box = svg.value.getBoundingClientRect();
    return {
        x: view.value.x + ((event.clientX - box.left) / box.width) * view.value.w,
        y: view.value.y + ((event.clientY - box.top) / box.height) * view.value.h,
    };
}

function onWheel(event) {
    const factor = Math.exp(-event.deltaY * 0.002);
    // Fully out, scrolling down scrolls the page: the map never traps it.
    if (factor < 1 && zoom.value <= 1.001) return;
    event.preventDefault();
    cancelAnimationFrame(glide);
    const p = gridPoint(event);
    view.value = zoomedView(factor, p.x, p.y);
}

function onDoubleClick(event) {
    const p = gridPoint(event);
    glideTo(zoomedView(2, p.x, p.y));
}

// A press that moves more than a few pixels is a drag: it pans, and the
// click that ends it doesn't pick the place under the pointer.
let press = null;
const dragging = ref(false);
function onPointerDown(event) {
    if (event.button !== 0) return;
    press = { x: event.clientX, y: event.clientY, view: { ...view.value }, id: event.pointerId };
    dragging.value = false;
}
function onPointerMove(event) {
    if (!press) return;
    const dx = event.clientX - press.x;
    const dy = event.clientY - press.y;
    if (!dragging.value && Math.hypot(dx, dy) > 3) {
        dragging.value = true;
        svg.value.setPointerCapture(press.id);
        cancelAnimationFrame(glide);
    }
    if (!dragging.value) return;
    const box = svg.value.getBoundingClientRect();
    view.value = clamp({ ...press.view, x: press.view.x - (dx / box.width) * press.view.w, y: press.view.y - (dy / box.height) * press.view.h });
}
function onPointerUp() {
    press = null;
    // Let this click (if any) see that it ended a drag, then forget it.
    setTimeout(() => (dragging.value = false));
}

function pick(dot, event) {
    // Not after a drag, and only the first click of a double-click (which zooms).
    if (!dragging.value && event.detail <= 1) emit('pick', dot, event.altKey);
}

function onKey(event) {
    const keys = {
        '+': zoomIn, '=': zoomIn, '-': zoomOut, _: zoomOut, 0: reset,
        ArrowLeft: () => pan(-0.2, 0), ArrowRight: () => pan(0.2, 0), ArrowUp: () => pan(0, -0.2), ArrowDown: () => pan(0, 0.2),
    };
    if (keys[event.key] && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        keys[event.key]();
    }
}

// The level the zoom calls for, and the finest one loaded so far.
const wantedLevel = computed(() => Math.min(FINER.length - 1, Math.max(0, Math.floor(Math.log2(zoom.value + 1e-6)))));
watch(wantedLevel, async (wanted) => {
    for (let n = 1; n <= wanted; n++) {
        if (levels.value[n]) continue;
        const { LEVEL: finer } = await FINER[n]();
        const loaded = [...levels.value];
        loaded[n] = parseLevel(finer);
        levels.value = loaded;
    }
});
const shownLevel = computed(() => {
    for (let n = wantedLevel.value; n > 0; n--) if (levels.value[n]) return n;
    return 0;
});

const land = computed(() => {
    const grid = levels.value[shownLevel.value];
    const per = grid.cols / COLS;   // grid cells per map unit
    const { x, y, w, h } = view.value;
    const c0 = Math.max(0, Math.floor(x * per) - 1);
    const c1 = Math.min(grid.cols, Math.ceil((x + w) * per) + 1);
    const r0 = Math.max(0, Math.floor(y * per) - 1);
    const r1 = Math.min(grid.rows, Math.ceil((y + h) * per) + 1);
    const parts = [];
    for (let r = r0; r < r1; r++) {
        const cy = ((r + 0.5) / per).toFixed(4);
        for (const [start, length] of grid.runs[r]) {
            for (let c = Math.max(start, c0); c < Math.min(start + length, c1); c++) parts.push(`M${((c + 0.5) / per).toFixed(4)} ${cy}h0`);
        }
    }
    return { d: parts.join(''), width: 0.55 / per };
});

// --- places ---------------------------------------------------------------
// Drawn worst last, so a red dot is never hidden under a green one. A dot
// shrinks a little in grid units as you zoom in, so on screen it stays near
// its size and close places come apart instead of growing together.
const dots = computed(() =>
    props.points
        .map((point) => ({
            ...point,
            key: keyOf(point),
            x: ((point.lng + 180) / 360) * COLS,
            y: Math.min(ROWS, Math.max(0, ((LAT_TOP - point.lat) / (LAT_TOP - LAT_BOTTOM)) * ROWS)),
            r: Math.min(2.2, 0.55 + Math.sqrt(point.events) * 0.12) / zoom.value ** 0.7,
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
            <span class="text-[0.75rem] tabular-nums text-ink-faint">
                {{ points.length }} place{{ points.length === 1 ? '' : 's' }}<template v-if="zoom > 1.01"> · {{ zoom.toFixed(1) }}×</template>
            </span>
        </div>
        <div
            class="relative px-3 py-2 outline-none focus-visible:ring-1 focus-visible:ring-phosphor/40"
            tabindex="0"
            role="group"
            aria-label="Attack map. + and − zoom, the arrow keys pan, 0 shows the whole world."
            @keydown="onKey"
        >
            <!-- Top countries below filters by country from the keyboard, too. -->
            <svg
                ref="svg"
                :viewBox="`${view.x} ${view.y} ${view.w} ${view.h}`"
                class="block w-full touch-none select-none overflow-hidden"
                :class="dragging ? 'cursor-grabbing' : 'cursor-grab'"
                role="img"
                :aria-label="`Attack map: ${points.length} places in the last 24 hours`"
                @wheel="onWheel"
                @dblclick.prevent="onDoubleClick"
                @pointerdown="onPointerDown"
                @pointermove="onPointerMove"
                @pointerup="onPointerUp"
                @pointercancel="onPointerUp"
            >
                <defs>
                    <linearGradient id="map-sweep-trail" x1="0" x2="1">
                        <stop offset="0" stop-color="var(--color-phosphor)" stop-opacity="0" />
                        <stop offset="1" stop-color="var(--color-phosphor)" stop-opacity="0.18" />
                    </linearGradient>
                </defs>
                <path class="map-land" :d="land.d" stroke="var(--color-grid)" :stroke-width="land.width" stroke-linecap="round" fill="none" />
                <!-- The radar line keeps its width on screen at any zoom. -->
                <g class="map-sweep" aria-hidden="true">
                    <rect :x="-14 / zoom" y="0" :width="14 / zoom" :height="ROWS" fill="url(#map-sweep-trail)" />
                    <rect :x="-0.3 / zoom" y="0" :width="0.3 / zoom" :height="ROWS" fill="var(--color-phosphor)" opacity="0.45" />
                </g>
                <g v-for="dot in dots" :key="dot.key" class="map-place cursor-pointer" :data-kind="dot.kind" @click="pick(dot, $event)">
                    <title>{{ describe(dot) }}</title>
                    <circle v-if="pinging.has(dot.key)" class="map-ping" :cx="dot.x" :cy="dot.y" :r="dot.r" fill="none" :stroke="dot.colour" stroke-width="0.35" vector-effect="non-scaling-stroke" />
                    <circle class="map-dot" :cx="dot.x" :cy="dot.y" :r="dot.r" :fill="dot.colour" />
                </g>
            </svg>
            <p v-if="!points.length" class="pointer-events-none absolute inset-0 flex items-center justify-center text-[0.75rem] text-ink-faint">
                No located traffic in the last 24 hours
            </p>
            <div class="absolute right-4 top-3 flex flex-col border border-edge bg-panel/90 text-[0.8125rem] leading-none">
                <button type="button" class="px-1.5 py-1 text-ink-dim hover:text-phosphor disabled:opacity-30" :disabled="zoom >= MAX_ZOOM - 0.01" aria-label="Zoom in" title="Zoom in (+)" @click="zoomIn">+</button>
                <button type="button" class="border-t border-edge px-1.5 py-1 text-ink-dim hover:text-phosphor disabled:opacity-30" :disabled="zoom <= 1.01" aria-label="Zoom out" title="Zoom out (−)" @click="zoomOut">−</button>
                <button type="button" class="border-t border-edge px-1.5 py-1 text-ink-dim hover:text-phosphor disabled:opacity-30" :disabled="zoom <= 1.01" aria-label="Whole world" title="Whole world (0)" @click="reset">⟲</button>
            </div>
        </div>
    </div>
</template>
