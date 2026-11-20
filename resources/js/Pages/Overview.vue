<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { router, Head, usePage, Link } from '@inertiajs/vue3';
import StatTile from '../Components/StatTile.vue';
import SeverityBadge from '../Components/SeverityBadge.vue';
import TrafficChart from '../Components/TrafficChart.vue';
import BawlsMark from '../Components/BawlsMark.vue';
import { clock } from '../settings';

const page = usePage();

const props = defineProps({
    stats: Object,
    traffic: Array,
    recentEvents: Array,
    openAlerts: Array,
    topSources: Array,
    sensors: Array,
    aggregates: Object,
    filters: Object,
});

const filters = ref({ ...props.filters });

/**
 * Filters are server-side, so changing one is just a reload with new query
 * params. `preserveState` keeps the live-poll timer and scroll position
 * rather than remounting the page on every keystroke.
 */
function applyFilters() {
    router.get('/', pruned(filters.value), {
        preserveState: true,
        preserveScroll: true,
        replace: true,
    });
}

function pruned(values) {
    return Object.fromEntries(
        Object.entries(values).filter(([, v]) => v && v !== 'all')
    );
}

function clearFilters() {
    filters.value = { direction: 'all', action: 'all', q: '' };
    applyFilters();
}

const filtersActive = computed(
    () => Object.keys(pruned(filters.value)).length > 0
);

let searchTimer = null;
function onSearch() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(applyFilters, 350);
}

const live = ref(true);
const lastRefresh = ref(new Date());
let timer = null;

function refresh() {
    router.reload({
        only: ['stats', 'traffic', 'recentEvents', 'openAlerts', 'topSources', 'sensors', 'aggregates'],
        data: pruned(filters.value),
        onSuccess: () => (lastRefresh.value = new Date()),
    });
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
    timer = setInterval(refresh, 5000);
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
    { key: 'at', label: `Time · ${page.props.settings.timezone_label}` },
    { key: 'proto', label: 'Proto' },
    { key: 'src', label: 'Source' },
    { key: 'dst', label: 'Destination' },
    { key: 'process', label: 'Process' },
    { key: 'action', label: 'Action' },
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
    const rows = props.recentEvents.map((event, index) => ({ event, index }));

    return rows
        .sort((a, b) => {
            if (key === 'at') return (b.index - a.index) * flip;   // index 0 = newest
            const x = a.event[key], y = b.event[key];
            if (x == null || y == null) return (x == null) - (y == null) || a.index - b.index; // blanks last
            return collator.compare(x, y) * flip || a.index - b.index;
        })
        .map((row) => row.event);
});

const actionTone = {
    blocked: 'text-alarm',
    failed: 'text-amber',
    allowed: 'text-phosphor',
    accepted: 'text-signal',
};
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
                    <p class="text-[12px] uppercase tracking-[0.2em] text-ink-faint">
                        Honeypot console
                    </p>
                </div>
            </div>

            <div class="flex items-center gap-3 whitespace-nowrap">
                <Link href="/ip" class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">OSINT ▸</Link>
                <Link href="/credentials" class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Creds</Link>
                <a href="/blocklist" target="_blank" class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Blocklist</a>
                <input
                    v-model="filters.q"
                    type="search"
                    placeholder="ip or process"
                    class="w-40 border border-edge bg-void px-2 py-1 text-[13px] text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                    @input="onSearch"
                />
                <select
                    v-model="filters.direction"
                    class="w-28 border border-edge bg-void px-2 py-1 text-[13px] text-ink outline-none focus:border-phosphor/60"
                    @change="applyFilters"
                >
                    <option value="all">direction</option>
                    <option value="in">inbound</option>
                    <option value="out">outbound</option>
                </select>
                <select
                    v-model="filters.action"
                    class="w-28 border border-edge bg-void px-2 py-1 text-[13px] text-ink outline-none focus:border-phosphor/60"
                    @change="applyFilters"
                >
                    <option value="all">action</option>
                    <option value="blocked">blocked</option>
                    <option value="allowed">allowed</option>
                    <option value="accepted">accepted</option>
                </select>
                <button
                    v-if="filtersActive"
                    class="border border-amber/50 px-2 py-1 text-[13px] uppercase tracking-[0.1em] text-amber hover:bg-amber/10"
                    @click="clearFilters"
                >
                    Clear
                </button>

                <span class="whitespace-nowrap border-l border-grid pl-3 text-[13px] tabular-nums text-ink-faint">
                    {{ clock(lastRefresh, page.props.settings.timezone) }} {{ page.props.settings.timezone_label }}
                </span>
                <button
                    class="border px-3 py-1 text-[13px] uppercase tracking-[0.15em] transition-colors"
                    :class="live
                        ? 'border-phosphor/50 text-phosphor hover:bg-phosphor/10'
                        : 'border-edge text-ink-dim hover:text-ink'"
                    @click="toggleLive"
                >
                    <span v-if="live" class="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-phosphor pulse" />
                    {{ live ? 'Live' : 'Paused' }}
                </button>
                <button
                    class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:text-ink"
                    @click="refresh"
                >
                    Refresh
                </button>
                <div class="flex items-center gap-2 border-l border-grid pl-4">
                    <span class="text-[13px] text-ink-faint">{{ page.props.auth?.user?.name }}</span>
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
                        class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:border-alarm/50 hover:text-alarm"
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
                <TrafficChart :series="traffic" />

                <!-- Fills the column down to the bottom of the right rail (the
                     Signatures box). The table scrolls inside an absolutely
                     positioned layer so its rows never make the page taller. -->
                <div class="flex flex-1 flex-col border border-grid bg-panel">
                    <div class="flex items-baseline justify-between border-b border-grid px-4 py-2">
                        <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Live event stream</h2>
                        <span class="text-[12px] text-ink-faint">
                            {{ filtersActive ? 'filtered — ' : '' }}most recent {{ recentEvents.length }}
                        </span>
                    </div>

                    <div class="relative min-h-[26rem] flex-1">
                        <div class="absolute inset-0 overflow-y-auto">
                            <table class="w-full text-[13px]">
                                <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                                    <tr class="text-left">
                                        <th
                                            v-for="col in columns"
                                            :key="col.key"
                                            class="p-0 font-normal"
                                            :aria-sort="sort.key === col.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'"
                                        >
                                            <button
                                                type="button"
                                                class="flex w-full items-center gap-1 px-3 py-1.5 text-left hover:text-phosphor"
                                                :class="sort.key === col.key ? 'text-ink' : ''"
                                                @click="sortBy(col.key)"
                                            >
                                                {{ col.label }}
                                                <!-- Always takes its space, so the header never shifts. -->
                                                <span class="inline-block w-2 text-[10px]" :class="sort.key === col.key ? 'text-phosphor' : 'invisible'">
                                                    {{ sort.key === col.key && sort.dir === 'asc' ? '▲' : '▼' }}
                                                </span>
                                            </button>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr
                                        v-for="event in sortedEvents"
                                        :key="event.id"
                                        class="border-t border-grid/60 hover:bg-panel-lit"
                                    >
                                        <td class="px-3 py-1 tabular-nums text-ink-faint">{{ event.at }}</td>
                                        <td class="px-3 py-1 uppercase text-signal">{{ event.proto }}</td>
                                        <td class="px-3 py-1 tabular-nums">
                                            <Link :href="`/ip/${event.src_ip}`" class="text-ink hover:text-phosphor hover:underline">{{ event.src }}</Link>
                                        </td>
                                        <td class="px-3 py-1 tabular-nums text-ink-dim">{{ event.dst }}</td>
                                        <td class="px-3 py-1 text-amber">{{ event.process ?? '' }}</td>
                                        <td class="px-3 py-1 uppercase" :class="actionTone[event.action]">
                                            {{ event.action }}
                                        </td>
                                    </tr>
                                    <tr v-if="!recentEvents.length">
                                        <td colspan="6" class="px-3 py-6 text-center text-ink-faint">
                                            {{ filtersActive ? 'No events match these filters.' : 'No events yet — is a sensor running?' }}
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right rail -->
            <div class="space-y-3">
                <div class="border bg-panel"
                     :class="openAlerts.length ? 'border-alarm/40 glow-box' : 'border-grid'">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[13px] uppercase tracking-[0.2em]"
                            :class="openAlerts.length ? 'text-alarm' : 'text-ink-dim'">
                            Open alerts
                        </h2>
                    </div>
                    <div class="max-h-72 overflow-y-auto">
                        <div v-if="!openAlerts.length" class="px-4 py-6 text-center text-[13px] text-ink-faint">
                            All quiet. No detections in the active windows.
                        </div>
                        <div
                            v-for="alert in openAlerts"
                            :key="alert.id"
                            class="border-t border-grid/60 px-4 py-2 first:border-t-0"
                        >
                            <div class="flex items-center gap-2">
                                <SeverityBadge :severity="alert.severity" />
                                <span class="text-[12px] uppercase tracking-wider text-ink-faint">
                                    {{ alert.rule.replace('_', ' ') }}
                                </span>
                            </div>
                            <p class="mt-1 text-[13px] leading-snug">{{ alert.title }}</p>
                            <div class="mt-0.5 flex items-center gap-3 text-[12px] text-ink-faint">
                                <span>{{ alert.event_count }} events · {{ alert.last_seen }}</span>
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
                        <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Top sources · 24h</h2>
                    </div>
                    <table class="w-full text-[13px]">
                        <tbody>
                            <tr v-for="source in topSources" :key="source.ip" class="border-t border-grid/60">
                                <td class="px-4 py-1 tabular-nums">
                                    <Link :href="`/ip/${source.ip}`" class="text-ink hover:text-phosphor hover:underline">{{ source.ip }}</Link>
                                </td>
                                <td class="px-2 py-1 text-right tabular-nums text-ink-dim">{{ source.ports }}p</td>
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
                        <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Sensors</h2>
                    </div>
                    <div v-for="sensor in sensors" :key="sensor.name"
                         class="flex items-center justify-between border-t border-grid/60 px-4 py-1.5 text-[13px] first:border-t-0">
                        <div class="flex items-center gap-2">
                            <span class="h-1.5 w-1.5 rounded-full"
                                  :class="sensor.online ? 'bg-phosphor' : 'bg-ink-faint'" />
                            <span>{{ sensor.name }}</span>
                        </div>
                        <span class="tabular-nums text-ink-faint">
                            {{ sensor.online ? sensor.events.toLocaleString() : (sensor.last_seen ?? 'never') }}
                        </span>
                    </div>
                    <div v-if="!sensors.length" class="px-4 py-4 text-center text-[13px] text-ink-faint">
                        No sensors registered.
                    </div>
                </div>

                <!-- What the decoy is drawing · 24h -->
                <div v-if="aggregates" class="border border-grid bg-panel">
                    <div class="border-b border-grid px-4 py-2">
                        <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Top probed paths · 24h</h2>
                    </div>
                    <table class="w-full text-[13px]">
                        <tbody>
                            <tr v-for="p in aggregates.paths" :key="p.path" class="border-t border-grid/60">
                                <!-- w-full + max-w-0 together: max-width:0 alone lets Firefox
                                     collapse this column to 0px (the paths vanished). -->
                                <td class="w-full max-w-0 truncate px-4 py-1 text-ink-dim" :title="p.path">{{ p.path }}</td>
                                <td class="whitespace-nowrap px-4 py-1 text-right tabular-nums text-phosphor">{{ p.hits.toLocaleString() }}</td>
                            </tr>
                            <tr v-if="!aggregates.paths.length"><td class="px-4 py-4 text-center text-ink-faint">No decoy hits.</td></tr>
                        </tbody>
                    </table>
                </div>

                <div v-if="aggregates" class="grid grid-cols-2 gap-3">
                    <div class="border border-grid bg-panel">
                        <div class="border-b border-grid px-4 py-2">
                            <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Signatures</h2>
                        </div>
                        <table class="w-full text-[13px]">
                            <tbody>
                                <tr v-for="s in aggregates.signatures" :key="s.signature" class="border-t border-grid/60">
                                    <td class="px-3 py-1 uppercase tracking-wider"
                                        :class="s.signature === 'benign' ? 'text-ink-faint' : 'text-amber'">{{ s.signature }}</td>
                                    <td class="px-3 py-1 text-right tabular-nums">{{ s.hits.toLocaleString() }}</td>
                                </tr>
                                <tr v-if="!aggregates.signatures.length"><td class="px-3 py-3 text-center text-ink-faint">—</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="border border-grid bg-panel">
                        <div class="border-b border-grid px-4 py-2">
                            <h2 class="text-[13px] uppercase tracking-[0.2em] text-ink-dim">Top countries</h2>
                        </div>
                        <table class="w-full text-[13px]">
                            <tbody>
                                <tr v-for="c in aggregates.countries" :key="c.country" class="border-t border-grid/60">
                                    <td class="px-3 py-1 tabular-nums">{{ c.country }}</td>
                                    <td class="px-3 py-1 text-right tabular-nums text-phosphor">{{ c.n }}</td>
                                </tr>
                                <tr v-if="!aggregates.countries.length"><td class="px-3 py-3 text-center text-ink-faint">no geo yet</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
