<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { router, Head, usePage, Link } from '@inertiajs/vue3';
import StatTile from '../Components/StatTile.vue';
import SeverityBadge from '../Components/SeverityBadge.vue';
import TrafficChart from '../Components/TrafficChart.vue';
import BawlsMark from '../Components/BawlsMark.vue';
import StreamFilterBar from '../Components/StreamFilterBar.vue';
import EventDetails from '../Components/EventDetails.vue';
import DossierLink from '../Components/DossierLink.vue';
import { clock } from '../settings';
import { combine, pickHour, pickedHour, quote } from '../stream';

const page = usePage();

const props = defineProps({
    stats: Object,
    traffic: Array,
    stream: Object, // { filter, rows, matched, limit, error }
    range: String, // the chart's range: '24h' or '7d'
    openAlerts: Array,
    topSources: Array,
    sensors: Array,
    aggregates: Object,
    unrecognised: Object, // { days, hits, sources, rows: [{ method, path, hits, sources, last_seen, query, queries }] }
});

// The stream's display filter is server-side (App\Services\DisplayFilter)
// and lives in the URL (?f=), so reload, Back and shared links keep it.
// `preserveState` keeps the live-poll timer and scroll position.
function applyFilter(text) {
    router.get('/', { ...(text ? { f: text } : {}), ...(props.range !== '24h' ? { range: props.range } : {}) }, {
        preserveState: true,
        preserveScroll: true,
        replace: true,
    });
}

// Click anything to add it to the filter; Alt-click to exclude it.
function addFilter(condition, exclude = false) {
    applyFilter(combine(props.stream.filter, condition, exclude));
}

const hint = (condition) => `Filter: ${condition} · Alt-click to exclude`;

// A digest row as a stream filter: the same requests the digest counted
// (DashboardController::unrecognised), so "/" shows its probes and not every
// visit to the home page.
const digestFilter = (row) => [
    'site == decoy',
    `path == ${quote(row.path)}`,
    `method == ${quote(row.method)}`,
    'sig in {benign scanner_ua}',
    ...(['GET', 'HEAD'].includes(row.method) ? ['(query != "" || !(status in {200 503}))'] : []),
].join(' && ');

// A filter that doesn't parse leaves the last good rows on screen.
const shown = ref(props.stream);
watch(() => props.stream, (stream) => {
    if (!stream.error) shown.value = stream;
});

// A chart bar narrows the stream to its hour: picking another hour moves
// the filter there, and picking the same one again clears it. Alt-click
// adds the hour as an exclusion instead.
function pickBar(point, exclude) {
    exclude
        ? addFilter(`time >= ${quote(point.from)} && time < ${quote(point.to)}`, true)
        : applyFilter(pickHour(props.stream.filter, point.from, point.to));
}

// The chart bar whose hour the filter is narrowed to, if any.
const selectedHour = computed(() => pickedHour(props.stream.filter));

const STEP = 200;
const canLoadOlder = computed(() => shown.value.rows.length < shown.value.matched && shown.value.limit < 1000);

const live = ref(true);
const lastRefresh = ref(new Date());
let timer = null;

// The list holds still while the pointer is over it: the live refresh skips
// the stream until the pointer leaves, so a row can't move under a click.
const holding = ref(false);
let releaseTimer = null;

function refresh(limit = props.stream.limit, withStream = !holding.value) {
    router.reload({
        only: ['stats', 'traffic', ...(withStream ? ['stream'] : []), 'openAlerts', 'topSources', 'sensors', 'aggregates'],
        data: limit > STEP ? { limit } : {},
        onSuccess: () => (lastRefresh.value = new Date()),
    });
}

// The chart's range rides in the URL too, so the live refresh keeps it.
function setRange(range) {
    router.reload({ only: ['range', 'traffic'], data: { range } });
}

function loadOlder() {
    refresh(props.stream.limit + STEP, true);
}

function hold() {
    clearTimeout(releaseTimer);
    holding.value = true;
}

function release() {
    clearTimeout(releaseTimer);
    releaseTimer = setTimeout(() => {
        holding.value = false;
        if (live.value) refresh();
    }, 400);
}

// Rows that arrived since the last refresh flash briefly. A new filter or a
// longer list is a different list, so nothing in it counts as new.
const fresh = ref(new Set());
let seen = { key: null, ids: new Set() };
watch(shown, (stream) => {
    const key = `${stream.filter}|${stream.limit}`;
    const ids = new Set(stream.rows.map((row) => row.id));
    fresh.value = key === seen.key ? new Set([...ids].filter((id) => !seen.ids.has(id))) : new Set();
    seen = { key, ids };
}, { immediate: true });

// The selected event opens in the details pane; arrow keys move the selection.
const selected = ref(null);

function select(id) {
    selected.value = selected.value === id ? null : id;
}

function step(delta) {
    const rows = sortedEvents.value;
    if (!rows.length) return;
    const at = rows.findIndex((row) => row.id === selected.value);
    const next = rows[Math.min(rows.length - 1, Math.max(0, at === -1 ? 0 : at + delta))];
    selected.value = next.id;
    nextTick(() => document.getElementById(`event-${next.id}`)?.scrollIntoView({ block: 'nearest' }));
}

function ackAlert(id) {
    router.post(`/alerts/${id}/ack`, {}, { preserveScroll: true });
}

function resolveAlert(id) {
    router.post(`/alerts/${id}/resolve`, {}, { preserveScroll: true });
}

function toggleLive() {
    live.value = !live.value;
    live.value ? start() : stop();
}

function start() {
    stop();
    timer = setInterval(() => refresh(), 5000);
}

function stop() {
    if (timer) {
        clearInterval(timer);
        timer = null;
    }
}

onMounted(start);
onUnmounted(stop);

// Click a column to sort the stream; click again to flip it. Sorting is local
// to the rows on screen and survives the live refresh. "Time" is the server's
// own order (newest first), so it stays right across midnight.
const columns = computed(() => [
    { key: 'id', label: 'No.', width: 'w-20' },
    { key: 'at', label: `Time · ${page.props.settings.timezone_label}`, width: 'w-32' },
    { key: 'src', label: 'Source', width: 'w-64' },
    { key: 'dst', label: 'Destination', width: 'w-44' },
    { key: 'proto', label: 'Proto', width: 'w-20' },
    { key: 'info', label: 'Info', width: '' },
]);
const sort = ref({ key: 'at', dir: 'desc' });
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

function sortBy(key) {
    sort.value = sort.value.key === key
        ? { key, dir: sort.value.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: key === 'at' ? 'desc' : 'asc' };
}

const sortedEvents = computed(() => {
    const { key, dir } = sort.value;
    const flip = dir === 'asc' ? 1 : -1;
    const rows = shown.value.rows.map((event, index) => ({ event, index }));

    return rows
        .sort((a, b) => {
            if (key === 'at') return (b.index - a.index) * flip;   // index 0 = newest
            const x = a.event[key], y = b.event[key];
            if (x == null || y == null) return (x == null) - (y == null) || a.index - b.index; // blanks last
            return collator.compare(x, y) * flip || a.index - b.index;
        })
        .map((row) => row.event);
});

// Wireshark-style colouring rules. The Info text also names what happened
// (the signature, "blocked"), so the colour is never the only signal.
const kindTone = {
    exploit: 'text-alarm',
    login: 'text-signal',
    scan: 'text-amber',
    page: 'text-ink-dim',
    firewall: 'text-ink-faint',
    other: 'text-ink',
};
const kindBar = {
    exploit: 'border-l-alarm',
    login: 'border-l-signal',
    scan: 'border-l-amber',
    page: 'border-l-transparent',
    firewall: 'border-l-transparent',
    other: 'border-l-transparent',
};
const legend = [
    ['exploit', 'bg-alarm'],
    ['login', 'bg-signal'],
    ['scan', 'bg-amber'],
    ['page view', 'bg-ink-dim'],
    ['firewall', 'bg-ink-faint'],
];
</script>

<template>
    <Head title="Overview" />

    <div class="min-h-screen bg-void px-5 py-4">
        <!-- Header: icon sits inline to the left of the title; every control
             lives on the right of this same row rather than in a second bar. -->
        <header class="mb-4 flex items-center justify-between border-b border-grid pb-3">
            <div class="flex items-center gap-3">
                <BawlsMark />
                <div>
                    <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">BAWLS</h1>
                    <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">
                        Honeypot console
                    </p>
                </div>
            </div>

            <div class="flex items-center gap-3 whitespace-nowrap">
                <Link href="/ip" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">OSINT ▸</Link>
                <Link href="/credentials" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Creds</Link>
                <Link href="/lists" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Lists</Link>

                <span class="whitespace-nowrap border-l border-grid pl-3 text-[0.8125rem] tabular-nums text-ink-faint">
                    {{ clock(lastRefresh, page.props.settings.timezone) }} {{ page.props.settings.timezone_label }}
                </span>
                <button
                    class="border px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] transition-colors"
                    :class="live
                        ? 'border-phosphor/50 text-phosphor hover:bg-phosphor/10'
                        : 'border-edge text-ink-dim hover:text-ink'"
                    @click="toggleLive"
                >
                    <span v-if="live" class="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-phosphor pulse" />
                    {{ live ? 'Live' : 'Paused' }}
                </button>
                <button
                    class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:text-ink"
                    @click="refresh(stream.limit, true)"
                >
                    Refresh
                </button>
                <div class="flex items-center gap-2 border-l border-grid pl-4">
                    <span class="text-[0.8125rem] text-ink-faint">{{ page.props.auth?.user?.name }}</span>
                    <Link
                        href="/settings"
                        title="Settings"
                        aria-label="Settings"
                        class="border border-edge p-1.5 text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
                    >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                            <circle cx="12" cy="12" r="3.2" />
                            <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" />
                        </svg>
                    </Link>
                    <button
                        class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-alarm/50 hover:text-alarm"
                        @click="router.post('/logout')"
                    >
                        Sign out
                    </button>
                </div>
            </div>
        </header>

        <!-- Stat row -->
        <section class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-7">
            <StatTile label="Events 24h" :value="stats.events_24h.toLocaleString()" tone="normal" />
            <StatTile label="Decoy hits 24h" :value="stats.decoy_24h.toLocaleString()" tone="warn" />
            <StatTile label="Blocked 24h" :value="stats.blocked_24h.toLocaleString()" tone="warn" />
            <StatTile
                label="Open alerts"
                :value="stats.alerts_open"
                :tone="stats.alerts_open > 0 ? 'alarm' : 'idle'"
            />
            <StatTile
                label="High+"
                :value="stats.alerts_critical"
                :tone="stats.alerts_critical > 0 ? 'alarm' : 'idle'"
            />
            <StatTile
                label="Sensors up"
                :value="`${stats.sensors_online}/${stats.sensors_total}`"
                :tone="stats.sensors_online === stats.sensors_total ? 'normal' : 'warn'"
            />
            <StatTile label="Events stored" :value="stats.events_total.toLocaleString()" tone="idle" />
        </section>

        <div class="grid gap-3 xl:grid-cols-3">
            <!-- Left: chart over the live stream -->
            <div class="flex flex-col gap-3 xl:col-span-2">
                <TrafficChart
                    :series="traffic"
                    :selected="selectedHour"
                    :range="range"
                    @range="setRange"
                    @pick="pickBar"
                />

                <!-- Fills the column down to the bottom of the right rail (the
                     Signatures box). The table scrolls inside an absolutely
                     positioned layer so its rows never make the page taller. -->
                <div class="flex flex-1 flex-col border border-grid bg-panel">
                    <div class="flex items-center gap-3 border-b border-grid px-4 py-2">
                        <h2 class="whitespace-nowrap text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Live event stream</h2>
                        <StreamFilterBar class="flex-1" :applied="stream.filter" :error="stream.error" @apply="applyFilter" />
                    </div>

                    <div
                        class="relative flex-1"
                        :class="selected ? 'min-h-[14rem]' : 'min-h-[26rem]'"
                        @mouseenter="hold"
                        @mouseleave="release"
                    >
                        <div
                            class="absolute inset-0 overflow-y-auto outline-none focus-visible:ring-1 focus-visible:ring-phosphor/40"
                            tabindex="0"
                            aria-label="Event stream. Up and down arrows move the selection; Escape closes the details."
                            @keydown.down.prevent="step(1)"
                            @keydown.up.prevent="step(-1)"
                            @keydown.esc="selected = null"
                        >
                            <table class="w-full table-fixed text-[0.8125rem]">
                                <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                                    <tr class="text-left">
                                        <th
                                            v-for="col in columns"
                                            :key="col.key"
                                            class="p-0 font-normal"
                                            :class="col.width"
                                            :aria-sort="sort.key === col.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'"
                                        >
                                            <button
                                                type="button"
                                                class="flex w-full items-center gap-1 whitespace-nowrap px-3 py-1.5 text-left hover:text-phosphor"
                                                :class="sort.key === col.key ? 'text-ink' : ''"
                                                @click="sortBy(col.key)"
                                            >
                                                {{ col.label }}
                                                <!-- Always takes its space, so the header never shifts. -->
                                                <span class="inline-block w-2 text-[0.625rem]" :class="sort.key === col.key ? 'text-phosphor' : 'invisible'">
                                                    {{ sort.key === col.key && sort.dir === 'asc' ? '▲' : '▼' }}
                                                </span>
                                            </button>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="event in sortedEvents"
                                        :id="`event-${event.id}`"
                                        :key="event.id"
                                        class="cursor-pointer border-l-2 border-t border-t-grid/60"
                                        :class="[
                                            kindBar[event.kind],
                                            selected === event.id ? 'bg-phosphor/10' : 'hover:bg-panel-lit',
                                            fresh.has(event.id) ? 'row-new' : '',
                                        ]"
                                        :aria-selected="selected === event.id"
                                        @click="select(event.id)"
                                    >
                                        <td class="px-3 py-1 tabular-nums text-ink-faint">{{ event.id }}</td>
                                        <td class="px-3 py-1 tabular-nums text-ink-faint">{{ event.at }}</td>
                                        <td class="px-3 py-1 tabular-nums">
                                            <div class="flex min-w-0 items-center justify-between gap-2">
                                                <button
                                                    type="button"
                                                    class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                                    :title="hint(`src == ${event.src_ip}`)"
                                                    @click.stop="addFilter(`src == ${event.src_ip}`, $event.altKey)"
                                                >{{ event.src }}</button>
                                                <DossierLink :ip="event.src_ip" />
                                            </div>
                                        </td>
                                        <td class="truncate px-3 py-1 tabular-nums text-ink-dim" :title="event.dst">{{ event.dst }}</td>
                                        <td class="px-3 py-1 text-signal">{{ event.proto }}</td>
                                        <td class="truncate px-3 py-1" :class="kindTone[event.kind]" :title="event.info">{{ event.info }}</td>
                                    </tr>
                                    <tr v-if="!shown.rows.length">
                                        <td colspan="6" class="px-3 py-6 text-center text-ink-faint">
                                            {{ shown.filter ? 'No events match this filter.' : 'No events yet — is a sensor running?' }}
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <EventDetails v-if="selected" :id="selected" @close="selected = null" @filter="addFilter" />

                    <!-- Status bar, as in Wireshark: what's shown out of what matches. -->
                    <div class="flex items-center justify-between gap-3 border-t border-grid px-4 py-1.5 text-[0.75rem] text-ink-faint">
                        <span class="tabular-nums">
                            Showing {{ shown.rows.length.toLocaleString() }} newest of
                            {{ shown.matched.toLocaleString() }} {{ shown.filter ? 'matching' : 'stored' }}
                            <span v-if="holding && live" class="text-ink-dim"> · held still while you point at it</span>
                        </span>
                        <span class="hidden items-center gap-3 lg:flex" aria-hidden="true">
                            <span v-for="[label, swatch] in legend" :key="label" class="flex items-center gap-1.5">
                                <span class="inline-block h-2 w-2" :class="swatch" />{{ label }}
                            </span>
                        </span>
                        <button
                            type="button"
                            class="border border-edge px-2 py-0.5 uppercase tracking-[0.1em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor disabled:opacity-40"
                            :disabled="!canLoadOlder"
                            :title="shown.limit >= 1000 && shown.rows.length < shown.matched ? 'The stream shows 1,000 at most: narrow the filter' : ''"
                            @click="loadOlder"
                        >Load older ▾</button>
                    </div>
                </div>
            </div>

            <!-- Right rail -->
            <div class="space-y-3">
                <div class="border bg-panel"
                     :class="openAlerts.length ? 'border-alarm/40 glow-box' : 'border-grid'">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[0.8125rem] uppercase tracking-[0.2em]"
                            :class="openAlerts.length ? 'text-alarm' : 'text-ink-dim'">
                            Open alerts
                        </h2>
                    </div>
                    <div class="max-h-72 overflow-y-auto">
                        <div v-if="!openAlerts.length" class="px-4 py-6 text-center text-[0.8125rem] text-ink-faint">
                            All quiet. No detections in the active windows.
                        </div>
                        <div
                            v-for="alert in openAlerts"
                            :key="alert.id"
                            class="border-t border-grid/60 px-4 py-2 first:border-t-0"
                        >
                            <div class="flex items-center gap-2">
                                <SeverityBadge :severity="alert.severity" />
                                <span class="text-[0.75rem] uppercase tracking-wider text-ink-faint">
                                    {{ alert.rule.replace('_', ' ') }}
                                </span>
                            </div>
                            <p class="mt-1 text-[0.8125rem] leading-snug">{{ alert.title }}</p>
                            <div class="mt-0.5 flex items-center gap-3 text-[0.75rem] text-ink-faint">
                                <span>{{ alert.event_count }} events · {{ alert.last_seen }}</span>
                                <button
                                    v-if="alert.src_ip"
                                    type="button"
                                    class="hover:text-phosphor hover:underline"
                                    :title="hint(`src == ${alert.src_ip}`)"
                                    @click="addFilter(`src == ${alert.src_ip}`, $event.altKey)"
                                >filter</button>
                                <Link v-if="alert.src_ip" :href="`/ip/${alert.src_ip}`" class="hover:text-phosphor hover:underline">dossier</Link>
                                <span class="ml-auto flex gap-2">
                                    <button class="text-ink-dim hover:text-amber" @click="ackAlert(alert.id)">ack</button>
                                    <button class="text-ink-dim hover:text-phosphor" @click="resolveAlert(alert.id)">resolve</button>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="border border-grid bg-panel">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Top sources · 24h</h2>
                    </div>
                    <table class="w-full text-[0.8125rem]">
                        <thead v-if="topSources.length" class="text-left text-ink-faint">
                            <tr>
                                <th class="px-4 py-1.5 font-normal">Address</th>
                                <th class="px-2 py-1.5 text-right font-normal" title="How many different ports on your server it tried">Ports</th>
                                <th class="px-4 py-1.5 text-right font-normal" title="Requests and blocked connections">Hits</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="source in topSources" :key="source.ip" class="border-t border-grid/60">
                                <td class="px-4 py-1 tabular-nums">
                                    <div class="flex min-w-0 items-center justify-between gap-2">
                                        <button
                                            type="button"
                                            class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                            :title="hint(`src == ${source.ip}`)"
                                            @click="addFilter(`src == ${source.ip}`, $event.altKey)"
                                        >{{ source.ip }}</button>
                                        <DossierLink :ip="source.ip" />
                                    </div>
                                </td>
                                <td class="px-2 py-1 text-right tabular-nums text-ink-dim">{{ source.ports }}</td>
                                <td class="px-4 py-1 text-right tabular-nums text-phosphor">
                                    {{ source.hits.toLocaleString() }}
                                </td>
                            </tr>
                            <tr v-if="!topSources.length">
                                <td class="px-4 py-4 text-center text-ink-faint">No traffic recorded.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="border border-grid bg-panel">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Sensors</h2>
                    </div>
                    <div v-for="sensor in sensors" :key="sensor.name"
                         class="flex items-center justify-between border-t border-grid/60 px-4 py-1.5 text-[0.8125rem] first:border-t-0">
                        <div class="flex items-center gap-2">
                            <span class="h-1.5 w-1.5 rounded-full"
                                  :class="sensor.online ? 'bg-phosphor' : 'bg-ink-faint'" />
                            <span>{{ sensor.name }}</span>
                        </div>
                        <span class="tabular-nums text-ink-faint">
                            {{ sensor.online ? sensor.events.toLocaleString() : (sensor.last_seen ?? 'never') }}
                        </span>
                    </div>
                    <div v-if="!sensors.length" class="px-4 py-4 text-center text-[0.8125rem] text-ink-faint">
                        No sensors registered.
                    </div>
                </div>

                <!-- What the decoy is drawing · 24h -->
                <div v-if="aggregates" class="border border-grid bg-panel">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Top probed paths · 24h</h2>
                    </div>
                    <table class="w-full text-[0.8125rem]">
                        <tbody>
                            <tr v-for="p in aggregates.paths" :key="p.path" class="border-t border-grid/60">
                                <!-- w-full + max-w-0 together: max-width:0 alone lets Firefox
                                     collapse this column to 0px (the paths vanished). -->
                                <td class="w-full max-w-0 truncate px-4 py-1">
                                    <button
                                        type="button"
                                        class="max-w-full truncate text-left text-ink-dim hover:text-phosphor hover:underline"
                                        :title="`${p.path}\n${hint(`path == ${quote(p.path)}`)}`"
                                        @click="addFilter(`path == ${quote(p.path)}`, $event.altKey)"
                                    >{{ p.path }}</button>
                                </td>
                                <td class="whitespace-nowrap px-4 py-1 text-right tabular-nums text-phosphor">{{ p.hits.toLocaleString() }}</td>
                            </tr>
                            <tr v-if="!aggregates.paths.length"><td class="px-4 py-4 text-center text-ink-faint">No decoy hits.</td></tr>
                        </tbody>
                    </table>
                </div>

                <div v-if="aggregates" class="grid grid-cols-2 gap-3">
                    <div class="border border-grid bg-panel">
                        <div class="border-b border-grid px-4 py-2">
                            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Signatures</h2>
                        </div>
                        <table class="w-full text-[0.8125rem]">
                            <tbody>
                                <tr v-for="s in aggregates.signatures" :key="s.signature" class="border-t border-grid/60">
                                    <td class="px-3 py-1">
                                        <button
                                            type="button"
                                            class="uppercase tracking-wider hover:underline"
                                            :class="s.signature === 'benign' ? 'text-ink-faint hover:text-ink' : 'text-amber hover:text-phosphor'"
                                            :title="hint(`sig == ${quote(s.signature)}`)"
                                            @click="addFilter(`sig == ${quote(s.signature)}`, $event.altKey)"
                                        >{{ s.signature }}</button>
                                    </td>
                                    <td class="px-3 py-1 text-right tabular-nums">{{ s.hits.toLocaleString() }}</td>
                                </tr>
                                <tr v-if="!aggregates.signatures.length"><td class="px-3 py-3 text-center text-ink-faint">—</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="border border-grid bg-panel">
                        <div class="border-b border-grid px-4 py-2">
                            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Top countries</h2>
                        </div>
                        <table class="w-full text-[0.8125rem]">
                            <tbody>
                                <tr v-for="c in aggregates.countries" :key="c.country" class="border-t border-grid/60">
                                    <td class="px-3 py-1 tabular-nums">
                                        <button
                                            type="button"
                                            class="hover:text-phosphor hover:underline"
                                            :title="hint(`country == ${quote(c.country)}`)"
                                            @click="addFilter(`country == ${quote(c.country)}`, $event.altKey)"
                                        >{{ c.country }}</button>
                                    </td>
                                    <td class="px-3 py-1 text-right tabular-nums text-phosphor">{{ c.n }}</td>
                                </tr>
                                <tr v-if="!aggregates.countries.length"><td class="px-3 py-3 text-center text-ink-faint">no geo yet</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- What the signatures missed this week -->
        <section v-if="unrecognised" class="mt-3 border border-grid bg-panel">
            <div class="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-grid px-4 py-2">
                <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Unrecognised probes · {{ unrecognised.days }} days</h2>
                <span class="text-[0.75rem] text-ink-faint">
                    {{ unrecognised.hits.toLocaleString() }} requests from {{ unrecognised.sources.toLocaleString() }} addresses matched no attack pattern
                </span>
            </div>
            <table class="w-full table-fixed text-[0.8125rem]">
                <thead class="text-left text-ink-faint">
                    <tr>
                        <th class="px-4 py-1.5 font-normal">Request</th>
                        <th class="w-28 px-3 py-1.5 text-right font-normal">Addresses</th>
                        <th class="w-28 px-3 py-1.5 text-right font-normal">Requests</th>
                        <th class="w-36 px-4 py-1.5 text-right font-normal">Last seen</th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for="row in unrecognised.rows" :key="`${row.method} ${row.path}`" class="border-t border-grid/60 align-top">
                        <td class="overflow-hidden px-4 py-1.5">
                            <div class="flex min-w-0 items-baseline gap-2">
                                <span v-if="row.method !== 'GET'" class="shrink-0 border border-amber/50 px-1 text-[0.6875rem] text-amber">{{ row.method }}</span>
                                <button
                                    type="button"
                                    class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                    :title="`${row.path}\n${hint(digestFilter(row))}`"
                                    @click="addFilter(digestFilter(row), $event.altKey)"
                                >{{ row.path }}</button>
                            </div>
                            <div v-if="row.query" class="truncate text-[0.75rem] text-ink-faint" :title="row.query">
                                ?{{ row.query }}<template v-if="row.queries > 1"> · {{ row.queries - 1 }} other {{ row.queries === 2 ? 'query' : 'queries' }}</template>
                            </div>
                        </td>
                        <td class="px-3 py-1.5 text-right tabular-nums text-phosphor">{{ row.sources.toLocaleString() }}</td>
                        <td class="px-3 py-1.5 text-right tabular-nums text-ink-dim">{{ row.hits.toLocaleString() }}</td>
                        <td class="whitespace-nowrap px-4 py-1.5 text-right text-ink-faint">{{ row.last_seen }}</td>
                    </tr>
                    <tr v-if="!unrecognised.rows.length">
                        <td colspan="4" class="px-4 py-4 text-center text-ink-faint">Nothing unrecognised this week.</td>
                    </tr>
                </tbody>
            </table>
            <p class="border-t border-grid px-4 py-2 text-[0.75rem] text-ink-faint">
                Decoy requests no attack pattern caught, with ordinary page views left out: unknown paths, query strings and unusual methods.
                Click one to see its requests in the stream. If it's an attack, its pattern can be added to the sensor's list so it's banned next time.
            </p>
        </section>
    </div>
</template>
