<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { router, Head, Link, usePage } from '@inertiajs/vue3';
import * as maplibregl from 'maplibre-gl';
import maplibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url';
import 'maplibre-gl/dist/maplibre-gl.css';
import SeverityBadge from '../Components/SeverityBadge.vue';
import BawlsMark from '../Components/BawlsMark.vue';
import { explain } from '../glossary';

// MapLibre 6 locates its worker at runtime (new URL('./maplibre-gl-worker.mjs',
// import.meta.url)), which Vite can't see, so the file never reached the build:
// the request 404'd and the map stayed blank. Importing it with ?url makes Vite
// emit it, and setWorkerUrl points MapLibre at the emitted file.
maplibregl.setWorkerUrl(maplibreWorkerUrl);

const props = defineProps({
    ips: Array,
    selected: Object,
    filters: Object,
});

const page = usePage();

const filters = ref({ ...props.filters });

function applyFilters() {
    router.get('/ip', pruned(filters.value), { preserveState: true, preserveScroll: true, replace: true });
}

function pruned(values) {
    return Object.fromEntries(Object.entries(values).filter(([, v]) => v !== '' && v !== false));
}

let searchTimer = null;
function onSearch() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(applyFilters, 300);
}

// Selecting a row only needs the detail pane; the list and map stay put.
function selectIp(ip) {
    router.visit(`/ip/${ip}`, { preserveState: true, preserveScroll: true, only: ['selected'] });
}

// Colour an IP by the worst thing known about it: alert/malicious = red,
// a suspicious signature = amber, otherwise the accent.
const SUSPECT = ['cve_probe', 'rce', 'sqli', 'traversal', 'login', 'dirbust'];
function tone(row) {
    if (row.alert_severity >= 4 || row.greynoise === 'malicious' || row.abuse_score >= 50) return '#ff2d55';
    if (SUSPECT.includes(row.signature)) return '#ff9500';
    return page.props.settings.accent;
}

// --- map ------------------------------------------------------------------
const mapEl = ref(null);
let map = null;
let markers = [];

// Bundled basemap: Natural Earth 1:50m country outlines (public domain),
// served from public/geo. No tile vendor, no API key, and nothing about which
// attacker locations we look at ever leaves the console.
const STYLE = {
    version: 8,
    sources: {
        countries: {
            type: 'geojson',
            data: new URL('/geo/countries.json', window.location.origin).href,
            attribution: 'Natural Earth',
        },
    },
    layers: [
        { id: 'sea', type: 'background', paint: { 'background-color': '#070b09' } },
        { id: 'land', type: 'fill', source: 'countries', paint: { 'fill-color': '#0f1c16' } },
        { id: 'borders', type: 'line', source: 'countries', paint: { 'line-color': page.props.settings.accent_dim, 'line-width': 0.6, 'line-opacity': 0.8 } },
    ],
};

// Pins are the listed addresses that have coordinates.
const points = computed(() => (props.ips ?? []).filter((p) => p.lat != null && p.lng != null));

/** Frame every pin on first load, so no attacker starts off-screen. */
function fitToPoints() {
    if (!map || !points.value.length) return;
    const bounds = new maplibregl.LngLatBounds();
    points.value.forEach((p) => bounds.extend([p.lng, p.lat]));
    map.fitBounds(bounds, { padding: 40, maxZoom: 3, duration: 0 });
}

function drawMarkers() {
    markers.forEach((m) => m.remove());
    markers = [];
    if (!map) return;
    for (const p of points.value) {
        const el = document.createElement('button');
        el.className = 'bawls-pin';
        el.style.cssText = `width:11px;height:11px;border-radius:50%;cursor:pointer;background:${tone(p)};`
            + `box-shadow:0 0 8px ${tone(p)};border:1px solid rgba(0,0,0,0.6)`;
        el.title = `${p.ip} · ${p.country ?? '?'} · AS${p.asn ?? '?'}`;
        el.addEventListener('click', () => selectIp(p.ip));
        markers.push(new maplibregl.Marker({ element: el }).setLngLat([p.lng, p.lat]).addTo(map));
    }
}

function flyToSelected() {
    const i = props.selected?.intel;
    if (map && i && i.lat != null && i.lng != null) {
        map.flyTo({ center: [i.lng, i.lat], zoom: 4, speed: 0.8 });
    }
}

onMounted(() => {
    map = new maplibregl.Map({
        container: mapEl.value,
        style: STYLE,
        center: [10, 25],
        zoom: 1.3,
        attributionControl: { compact: true },
    });
    map.on('load', () => { fitToPoints(); drawMarkers(); flyToSelected(); });
});

onUnmounted(() => { if (map) map.remove(); });

watch(points, drawMarkers);
watch(() => props.selected, flyToSelected);

const summaryTone = { alarm: 'text-alarm glow', amber: 'text-amber', signal: 'text-signal', dim: 'text-ink-dim' };
const signatures = ['cve_probe', 'rce', 'sqli', 'traversal', 'login', 'dirbust', 'scanner_ua', 'benign'];

function fmtPorts(ports) {
    return Array.isArray(ports) && ports.length ? ports.join(', ') : '—';
}

const assessTone = { spoofed: 'text-alarm', bot: 'text-amber', consistent: 'text-phosphor' };

function has(obj) {
    return obj && Object.keys(obj).length > 0;
}
</script>

<template>
    <Head title="OSINT" />

    <div class="flex h-screen flex-col bg-void px-5 py-4">
        <!-- Header: icon-left title, every control on the right of the same row. -->
        <header class="mb-3 flex items-center justify-between border-b border-grid pb-3">
            <div class="flex items-center gap-3">
                <BawlsMark />
                <div>
                    <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">BAWLS · OSINT</h1>
                    <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">Who's been knocking</p>
                </div>
            </div>

            <div class="flex items-center gap-3">
                <input
                    v-model="filters.q" type="search" placeholder="ip"
                    class="w-32 border border-edge bg-void px-2 py-1 text-[0.8125rem] text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                    @input="onSearch"
                />
                <select
                    v-model="filters.signature"
                    class="w-32 border border-edge bg-void px-2 py-1 text-[0.8125rem] text-ink outline-none focus:border-phosphor/60"
                    @change="applyFilters"
                >
                    <option value="">signature</option>
                    <option v-for="s in signatures" :key="s" :value="s">{{ s }}</option>
                </select>
                <input
                    v-model="filters.country" type="text" placeholder="cc" maxlength="2"
                    class="w-14 border border-edge bg-void px-2 py-1 text-[0.8125rem] uppercase text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                    @change="applyFilters"
                />
                <label class="flex items-center gap-1.5 text-[0.8125rem] text-ink-dim">
                    <input v-model="filters.alerts" type="checkbox" class="accent-phosphor" @change="applyFilters" />
                    alerts only
                </label>
                <Link
                    href="/"
                    class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
                >◂ Console</Link>
            </div>
        </header>

        <div class="grid min-h-0 flex-1 gap-3 xl:grid-cols-3">
            <!-- Left: the IP list -->
            <div class="flex min-h-0 flex-col border border-grid bg-panel xl:col-span-1">
                <div class="flex items-baseline justify-between border-b border-grid px-4 py-2">
                    <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Addresses</h2>
                    <span class="text-[0.75rem] text-ink-faint">{{ ips.length }}</span>
                </div>
                <div class="min-h-0 flex-1 overflow-y-auto">
                    <button
                        v-for="row in ips" :key="row.ip"
                        class="block w-full border-t border-grid/60 px-4 py-2 text-left first:border-t-0 hover:bg-panel-lit"
                        :class="selected && selected.ip === row.ip ? 'bg-panel-lit' : ''"
                        @click="selectIp(row.ip)"
                    >
                        <div class="flex items-center justify-between">
                            <span class="tabular-nums text-ink" :style="{ color: tone(row) }">{{ row.ip }}</span>
                            <span class="text-[0.75rem] text-ink-faint">{{ row.country ?? '··' }}</span>
                        </div>
                        <div class="mt-0.5 flex items-center gap-2 text-[0.75rem] text-ink-faint">
                            <span v-if="row.signature" class="uppercase tracking-wider" :title="explain($page.props.glossary, 'signatures', row.signature)">{{ row.signature }}</span>
                            <span v-if="row.tor" class="text-amber">TOR</span>
                            <span class="ml-auto tabular-nums">{{ row.hits }} hits · {{ row.last_seen }}</span>
                        </div>
                    </button>
                    <div v-if="!ips.length" class="px-4 py-6 text-center text-[0.8125rem] text-ink-faint">
                        No addresses match.
                    </div>
                </div>
            </div>

            <!-- Right: map over detail -->
            <div class="flex min-h-0 flex-col gap-3 xl:col-span-2">
                <div class="relative border border-grid bg-panel" style="height: 18.75rem">
                    <!-- Sized with h-full/w-full, not absolute inset-0: maplibre-gl.css is
                         unlayered, so its .maplibregl-map { position: relative } beats
                         Tailwind's layered .absolute and left the map 0px tall. -->
                    <div ref="mapEl" class="h-full w-full"></div>
                </div>

                <div class="min-h-0 flex-1 overflow-y-auto border border-grid bg-panel">
                    <div v-if="!selected" class="flex h-full items-center justify-center text-[0.8125rem] text-ink-faint">
                        Select an address to see its dossier.
                    </div>

                    <div v-else class="p-4">
                        <div class="mb-3 flex items-center gap-3 border-b border-grid pb-2">
                            <h2 class="text-base tabular-nums text-phosphor glow">{{ selected.ip }}</h2>
                            <span v-if="selected.intel?.checked_at" class="text-[0.75rem] text-ink-faint">
                                checked {{ selected.intel.checked_at }}
                            </span>
                            <span v-else class="text-[0.75rem] text-amber">not enriched yet</span>
                        </div>

                        <!-- The verdict at a glance, worst first. -->
                        <p v-if="selected.summary?.length" class="-mt-1 mb-3 text-[0.8125rem]">
                            <template v-for="(part, i) in selected.summary" :key="i">
                                <span v-if="i" class="text-ink-faint"> · </span>
                                <span :class="summaryTone[part.tone]">{{ part.text }}</span>
                            </template>
                        </p>

                        <!-- Intel -->
                        <div v-if="selected.intel && !selected.intel.is_private" class="mb-4 grid grid-cols-2 gap-x-6 gap-y-1 text-[0.8125rem] md:grid-cols-3">
                            <div><span class="text-ink-faint">Location </span>{{ [selected.intel.city, selected.intel.country].filter(Boolean).join(', ') || '—' }}</div>
                            <div><span class="text-ink-faint">ASN </span>{{ selected.intel.asn ? 'AS' + selected.intel.asn : '—' }}</div>
                            <div class="truncate"><span class="text-ink-faint">Org </span>{{ selected.intel.as_org ?? '—' }}</div>
                            <div class="truncate"><span class="text-ink-faint">rDNS </span>{{ selected.intel.rdns ?? '—' }}</div>
                            <div><span class="text-ink-faint">GreyNoise </span>
                                <span :class="selected.intel.greynoise === 'malicious' ? 'text-alarm' : 'text-ink'">{{ selected.intel.greynoise ?? '—' }}</span>
                            </div>
                            <div><span class="text-ink-faint">AbuseIPDB </span>
                                <span :class="selected.intel.abuse_score >= 50 ? 'text-alarm' : 'text-ink'">{{ selected.intel.abuse_score ?? '—' }}</span>
                                <span v-if="selected.intel.abuse_reports" class="text-ink-faint"> ({{ selected.intel.abuse_reports }})</span>
                            </div>
                            <div><span class="text-ink-faint">Tor exit </span><span :class="selected.intel.tor_exit ? 'text-amber' : 'text-ink'">{{ selected.intel.tor_exit ? 'yes' : 'no' }}</span></div>
                            <div class="truncate"><span class="text-ink-faint">Abuse </span>{{ selected.intel.abuse_contact ?? '—' }}</div>
                            <div class="col-span-2 truncate md:col-span-3"><span class="text-ink-faint">Open ports </span>{{ fmtPorts(selected.intel.open_ports) }}</div>
                        </div>
                        <div v-else class="mb-4 text-[0.8125rem] text-ink-faint">
                            {{ selected.intel?.is_private ? 'Private / LAN address — not looked up externally.' : 'No external intel yet. It is enriched on the next scheduled pass.' }}
                        </div>

                        <!-- What the client sent (passive) -->
                        <div v-if="selected.client" class="mb-4 border border-grid/60 bg-void/40 p-3">
                            <h3 class="mb-1 text-[0.75rem] uppercase tracking-[0.2em] text-ink-dim">What it sent · passive</h3>
                            <p class="text-[0.8125rem]" :class="assessTone[selected.client.assessment.verdict]">{{ selected.client.assessment.text }}</p>
                            <div class="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[0.75rem] text-ink-faint">
                                <span v-if="selected.client.http_fingerprint">fp <span class="tabular-nums text-ink-dim">{{ selected.client.http_fingerprint }}</span></span>
                                <span v-if="selected.client.accept">accept {{ selected.client.accept }}</span>
                                <span v-if="selected.client.accept_encoding">enc {{ selected.client.accept_encoding }}</span>
                                <span v-if="selected.client.accept_language">lang {{ selected.client.accept_language }}</span>
                                <span v-if="has(selected.client.client_hints)" class="text-phosphor">client-hints</span>
                                <span v-if="has(selected.client.sec_fetch)" class="text-phosphor">sec-fetch</span>
                            </div>
                            <div class="mt-1 break-all text-[0.75rem] text-ink-dim">{{ selected.client.user_agent || '(no user-agent)' }}</div>
                            <div v-if="selected.client.header_order.length" class="mt-1 break-all text-[0.75rem] text-ink-faint">
                                header order: {{ selected.client.header_order.join(' → ') }}
                            </div>
                        </div>

                        <!-- Active fingerprint, only if this IP ran the disclosed /browser-check -->
                        <div v-if="selected.browser" class="mb-4 border border-signal/40 bg-void/40 p-3">
                            <h3 class="mb-1 text-[0.75rem] uppercase tracking-[0.2em] text-signal">Active fingerprint · self-test · {{ selected.browser.when }}</h3>
                            <div class="text-[0.8125rem]">id <span class="tabular-nums text-phosphor">{{ selected.browser.fingerprint }}</span></div>
                            <div class="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[0.75rem] text-ink-faint">
                                <span v-if="selected.browser.signals.webgl_renderer">gpu {{ selected.browser.signals.webgl_renderer }}</span>
                                <span v-if="selected.browser.signals.screen">screen {{ selected.browser.signals.screen }}</span>
                                <span v-if="selected.browser.signals.timezone">tz {{ selected.browser.signals.timezone }}</span>
                                <span v-if="selected.browser.signals.fontCount != null">fonts {{ selected.browser.signals.fontCount }}</span>
                                <span v-if="selected.browser.signals.canvasRandomized != null">canvas {{ selected.browser.signals.canvasRandomized ? 'randomized' : 'stable' }}</span>
                                <span v-if="selected.browser.signals.webrtcIps && selected.browser.signals.webrtcIps.length">rtc {{ selected.browser.signals.webrtcIps.join(', ') }}</span>
                            </div>
                        </div>

                        <!-- Alerts -->
                        <div v-if="selected.alerts.length" class="mb-4 space-y-1">
                            <div v-for="(a, idx) in selected.alerts" :key="idx" class="flex items-center gap-2 text-[0.8125rem]">
                                <SeverityBadge :severity="a.severity" />
                                <span class="uppercase tracking-wider text-ink-faint">{{ a.rule.replace('_', ' ') }}</span>
                                <span>{{ a.title }}</span>
                                <span class="ml-auto text-ink-faint">{{ a.event_count }} · {{ a.last_seen }}</span>
                            </div>
                        </div>

                        <!-- Decoys served -->
                        <div v-if="selected.decoys.length" class="mb-4 flex flex-wrap gap-1">
                            <span v-for="d in selected.decoys" :key="d" class="border border-grid px-1.5 py-px text-[0.75rem] text-ink-dim">{{ d }}</span>
                        </div>

                        <!-- Timeline -->
                        <h3 class="mb-1 text-[0.75rem] uppercase tracking-[0.2em] text-ink-dim">Activity <span class="normal-case tracking-normal text-ink-faint">· times {{ page.props.settings.timezone_label }}</span></h3>
                        <table class="w-full text-[0.8125rem]">
                            <tbody>
                                <tr v-for="(e, idx) in selected.timeline" :key="idx" class="border-t border-grid/60">
                                    <td class="px-2 py-1 tabular-nums text-ink-faint">{{ e.at }}</td>
                                    <td class="px-2 py-1 uppercase text-signal">{{ e.method ?? e.proto }}</td>
                                    <td class="px-2 py-1 tabular-nums text-ink-dim">{{ e.path ?? ('port ' + (e.dst_port ?? '?')) }}</td>
                                    <td class="px-2 py-1">
                                        <span v-if="e.signature && e.signature !== 'benign'" class="uppercase tracking-wider" :title="explain($page.props.glossary, 'signatures', e.signature)"
                                              :class="SUSPECT.includes(e.signature) ? 'text-amber' : 'text-ink-faint'">{{ e.signature }}</span>
                                    </td>
                                    <td class="px-2 py-1 text-right text-ink-faint">{{ e.status ?? e.action }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<style>
/* Unlayered on purpose: maplibre-gl.css is unlayered too, so Tailwind's layered
   utilities can't restyle its controls. Turns the white attribution pill dark. */
.maplibregl-ctrl.maplibregl-ctrl-attrib {
    background: rgba(13, 20, 17, 0.85);
    color: #7f958a;
}
.maplibregl-ctrl.maplibregl-ctrl-attrib a { color: #9bb1a5; }
/* The (i) button is a black icon: invert it to light, with a light background
   that the same filter turns into the console's dark panel colour. */
.maplibregl-ctrl-attrib.maplibregl-compact .maplibregl-ctrl-attrib-button {
    background-color: rgb(242, 235, 238);
    filter: invert(1) hue-rotate(180deg);
}
</style>
