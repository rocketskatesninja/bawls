<script setup>
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { router, Head } from '@inertiajs/vue3';
import AttackMap from '../Components/AttackMap.vue';
import TrafficChart from '../Components/TrafficChart.vue';
import AlertsPanel from '../Components/Overview/AlertsPanel.vue';
import BootSequence from '../Components/Overview/BootSequence.vue';
import DecoyDrawPanels from '../Components/Overview/DecoyDrawPanels.vue';
import EventStreamPanel from '../Components/Overview/EventStreamPanel.vue';
import OverviewHeader from '../Components/Overview/OverviewHeader.vue';
import ProbeDigestPanel from '../Components/Overview/ProbeDigestPanel.vue';
import SensorsPanel from '../Components/Overview/SensorsPanel.vue';
import ShortcutsDialog from '../Components/Overview/ShortcutsDialog.vue';
import StatRow from '../Components/Overview/StatRow.vue';
import TopSourcesPanel from '../Components/Overview/TopSourcesPanel.vue';
import { chirp, setSoundOn, soundOn, unlockSound } from '../sound';
import { STREAM_PER_PAGE, save } from '../storage';
import { combine, pickHour, pickedHour, quote, savedPerPage } from '../stream';
import { useTabAlarm } from '../tabAlarm';

// The overview. This page owns the data and every request for it: the
// stream's filter and page (both in the URL), the live refresh, and what a
// click anywhere adds to the filter. The panels (Components/Overview) show
// what they're given and say what the viewer asked for.
//
// Every prop is worked out only when a request asks for it
// (DashboardController), so each request below names the props it wants.
const props = defineProps({
    stats: Object,
    traffic: Array,
    range: String, // the chart's range: '24h' or '7d'
    stream: Object, // { filter, rows, matched, page, per, pages, error } (App\Services\EventStream)
    openAlerts: Array,
    topSources: Array,
    sensors: Array,
    aggregates: Object,
    attackMap: Array, // [{ lat, lng, country, city, addresses, events, kind, last_seen }], worst first
    unrecognised: Object, // the weekly digest (App\Services\ProbeDigest)
});

// A filter that doesn't parse leaves the last good rows on screen. `shown`
// is what the page acts on; `stream` itself only feeds the filter bar, which
// shows the text as typed and its error.
const shown = ref(props.stream);
watch(() => props.stream, (stream) => {
    if (!stream.error) shown.value = stream;
});

// --- Requests ---------------------------------------------------------------

// A request of your own (a filter, a page, the chart's range) in flight: the
// live refresh waits for it. A refresh that started from the old address and
// landed last would put the old page back.
const navigating = ref(0);
const lastRefresh = ref(new Date());
const perPage = ref(savedPerPage());

/** Reload some props in place. `data` joins the address's query string. */
function reload(only, data, then) {
    navigating.value++;
    router.reload({
        only,
        data,
        onSuccess: () => {
            lastRefresh.value = new Date();
            then?.();
        },
        onFinish: () => navigating.value--,
    });
}

// The stream's display filter is server-side (App\Services\DisplayFilter)
// and lives in the URL (?f=), so reload, Back and shared links keep it. A new
// filter starts again on page 1. `preserveState` keeps this page's state
// (the live timer, the selection) and its scroll position.
function applyFilter(text) {
    navigating.value++;
    router.get('/', { ...(text ? { f: text } : {}), ...(props.range !== '24h' ? { range: props.range } : {}), per: perPage.value }, {
        preserveState: true,
        preserveScroll: true,
        replace: true,
        onFinish: () => navigating.value--,
    });
}

// Click anything to add it to the filter; Alt-click to exclude it.
function addFilter(condition, exclude = false) {
    applyFilter(combine(shown.value.filter, condition, exclude));
}

// A chart bar narrows the stream to its hour: picking another hour moves
// the filter there, and picking the same one again clears it. Alt-click
// adds the hour as an exclusion instead.
function pickBar(point, exclude) {
    exclude
        ? addFilter(`time >= ${quote(point.from)} && time < ${quote(point.to)}`, true)
        : applyFilter(pickHour(shown.value.filter, point.from, point.to));
}

function pickPlace(point, exclude) {
    if (point.country) addFilter(`country == ${quote(point.country)}`, exclude);
}

// The chart's range rides in the URL too, so the live refresh keeps it.
function setRange(range) {
    reload(['range', 'traffic'], { range });
}

// --- The stream's pages -----------------------------------------------------

// The stream shows a page of rows, 25, 50 or 100 as chosen (kept per
// browser). Page 1 is live; an older page holds still (new events would push
// every row along), and its number rides in the URL.
const streamPanel = ref(null);

function goToPage(number, per = perPage.value) {
    const target = Math.max(1, Math.min(number, Math.ceil(Math.max(1, shown.value.matched) / per)));
    reload(['stream'], { page: target > 1 ? target : undefined, per }, () => nextTick(() => streamPanel.value?.bringIntoView()));
}

// A new page size keeps the top row of this page on screen.
function setPerPage(per) {
    const firstRow = (shown.value.page - 1) * shown.value.per;
    perPage.value = per;
    save(STREAM_PER_PAGE, per);
    goToPage(Math.floor(firstRow / per) + 1, per);
}

// The server sent its default page size; this browser may have chosen another.
onMounted(() => {
    if (perPage.value !== props.stream.per) goToPage(shown.value.page);
});

// --- Live refresh -----------------------------------------------------------

const LIVE_EVERY_MS = 5000;
const live = ref(true);
let liveTimer = null;

// The list holds still while the pointer is over it: the live refresh skips
// the stream until the pointer leaves, so a row can't move under a click.
const holding = ref(false);
let releaseTimer = null;

// Everything but the weekly digest. The stream is left alone while you point
// at it, or while you're on an older page; the Refresh button always brings
// the page you're on.
function refresh(withStream = !holding.value && shown.value.page === 1) {
    if (navigating.value) return;
    reload(
        ['stats', 'traffic', ...(withStream ? ['stream'] : []), 'openAlerts', 'topSources', 'sensors', 'aggregates', 'attackMap'],
        { page: shown.value.page > 1 ? shown.value.page : undefined, per: perPage.value },
    );
}

function hold() {
    clearTimeout(releaseTimer);
    holding.value = true;
}

// A short wait, so crossing the list's edge and coming back doesn't refresh.
function release() {
    clearTimeout(releaseTimer);
    releaseTimer = setTimeout(() => {
        holding.value = false;
        if (live.value) refresh();
    }, 400);
}

function startLive() {
    stopLive();
    liveTimer = setInterval(() => refresh(), LIVE_EVERY_MS);
}

function stopLive() {
    clearInterval(liveTimer);
    liveTimer = null;
}

function toggleLive() {
    live.value = !live.value;
    live.value ? startLive() : stopLive();
}

onMounted(startLive);
onUnmounted(() => {
    stopLive();
    clearTimeout(releaseTimer);
});

// --- New alerts: the tab and the sound --------------------------------------

const { title, noteArrival } = useTabAlarm(() => props.stats.alerts_open, 'Overview');

// The new-alert sound: off by default, remembered per browser. After a
// reload the browser allows sound only once the page has been clicked or
// typed in, so the first click or key press starts it.
const sound = ref(soundOn());

function toggleSound() {
    sound.value = !sound.value;
    setSoundOn(sound.value);
    if (sound.value) unlockSound().then(chirp);   // a preview, so you know what to listen for
}

function wakeSound() {
    if (sound.value) unlockSound();
}

onMounted(() => {
    window.addEventListener('pointerdown', wakeSound, { once: true });
    window.addEventListener('keydown', wakeSound, { once: true });
});
onUnmounted(() => {
    window.removeEventListener('pointerdown', wakeSound);
    window.removeEventListener('keydown', wakeSound);
});

function alertArrived() {
    if (sound.value) chirp();
    noteArrival();
}

const shortcuts = ref(null);
</script>

<template>
    <Head :title="title" />

    <BootSequence :stats="stats" />
    <ShortcutsDialog ref="shortcuts" @focus-filter="streamPanel?.focusFilter()" />

    <div class="min-h-screen bg-void px-5 py-4">
        <OverviewHeader
            :live="live"
            :sound="sound"
            :last-refresh="lastRefresh"
            @toggle-live="toggleLive"
            @toggle-sound="toggleSound"
            @refresh="refresh(true)"
            @keys="shortcuts?.toggle()"
        />

        <StatRow :stats="stats" />

        <div class="grid gap-3 xl:grid-cols-3">
            <!-- Left: chart over the live stream -->
            <div class="flex flex-col gap-3 xl:col-span-2">
                <TrafficChart
                    :series="traffic"
                    :selected="pickedHour(shown.filter)"
                    :range="range"
                    @range="setRange"
                    @pick="pickBar"
                />

                <EventStreamPanel
                    ref="streamPanel"
                    :stream="stream"
                    :shown="shown"
                    :live="live"
                    :holding="holding"
                    :per-page="perPage"
                    @apply="applyFilter"
                    @filter="addFilter"
                    @go="goToPage"
                    @per="setPerPage"
                    @hold="hold"
                    @release="release"
                />
            </div>

            <!-- Right rail -->
            <div class="space-y-3">
                <AlertsPanel :alerts="openAlerts" :open="stats.alerts_open" :newest="stats.alerts_newest" @filter="addFilter" @arrived="alertArrived" />
                <AttackMap :points="attackMap" @pick="pickPlace" />
                <TopSourcesPanel :sources="topSources" @filter="addFilter" />
                <SensorsPanel :sensors="sensors" />
                <DecoyDrawPanels v-if="aggregates" :aggregates="aggregates" @filter="addFilter" />
            </div>
        </div>

        <ProbeDigestPanel v-if="unrecognised" :digest="unrecognised" @filter="addFilter" />
    </div>
</template>
