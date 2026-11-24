<script setup>
import { computed, nextTick, ref, watch } from 'vue';
import { usePage } from '@inertiajs/vue3';
import DossierLink from '../DossierLink.vue';
import EventDetails from '../EventDetails.vue';
import FilterButton from '../FilterButton.vue';
import StreamFilterBar from '../StreamFilterBar.vue';
import StreamPager from '../StreamPager.vue';
import { useMeaning } from '../../glossary';
import { KIND_BAR as kindBar, KIND_TONE as kindTone, LEGEND as legend } from '../../kinds';
import { reducedMotion } from '../../motion';
import { PER_PAGE, combine, filterChips, filterMinute, filterTerms, quote, removeChip, sinceChip, toggleTerm } from '../../stream';

// The live event stream: the filter bar, the filter as chips with one-click
// presets, a page of rows, the selected event's details, and the status bar.
// It has no scrollbar of its own (one would catch the mouse wheel and make
// the page hard to scroll): the page grows to fit the rows.
//
// The page owns the data and every request; this shows `shown` and says what
// the viewer asked for.
const props = defineProps({
    stream: { type: Object, required: true }, // as the server sent it: its filter text and error feed the filter bar
    shown: { type: Object, required: true }, // the last stream that parsed: the rows on screen
    live: { type: Boolean, required: true },
    holding: { type: Boolean, required: true }, // the live refresh is skipping the list while it's pointed at
    perPage: { type: Number, required: true },
});
const emit = defineEmits([
    'apply', // (text) replace the filter
    'filter', // (condition, exclude) add a condition to it
    'go', // (page)
    'per', // (rows per page)
    'hold', 'release', // the pointer entered or left the list
]);
const apply = (text) => emit('apply', text);
const filter = (condition, exclude) => emit('filter', condition, exclude);
const go = (page) => emit('go', page);

const page = usePage();
const meaning = useMeaning();

// The applied filter as chips (× takes one out), and one-click presets that
// add their term or take it out again.
const chips = computed(() => filterChips(props.shown.filter));
const presets = computed(() => {
    const text = props.shown.filter ?? '';
    const terms = filterTerms(text);
    const since = sinceChip(text);
    const toggle = (term) => ({ active: terms.includes(term), title: term, apply: () => apply(toggleTerm(text, term)) });
    const hourAgo = () => `time >= ${quote(filterMinute(new Date(Date.now() - 3600e3), page.props.settings.timezone))}`;

    return [
        // App\Models\Event::EXPLOIT_SIGNATURES
        { label: 'Exploits', ...toggle('sig in {cve_probe rce sqli traversal}') },
        { label: 'Logins', ...toggle('login') },
        { label: 'Real sites', ...toggle('(http && !decoy)') },
        {
            label: 'Last hour',
            active: !!since,
            title: since ? since.label : 'time >= an hour ago',
            apply: () => apply(since ? removeChip(text, since) : combine(text, hourAgo())),
        },
        { label: 'Banned', ...toggle('banned') },
    ];
});

const firstShown = computed(() => (props.shown.matched ? (props.shown.page - 1) * props.shown.per + 1 : 0));
const lastShown = computed(() => (props.shown.page - 1) * props.shown.per + props.shown.rows.length);

// Why the list isn't following new events right now, for the tag beside the
// panel's title; null while it is (or while live is switched off altogether,
// which the header's Live button already says).
const hold = computed(() => {
    if (!props.live) return null;
    if (props.shown.page > 1) return { label: 'held', why: 'An older page holds still; new events arrive on page 1' };
    if (props.holding) return { label: 'paused', why: 'The list holds still while you point at it' };
    return null;
});

// Export, as Wireshark's "Export Packet Dissections" with "Displayed": every
// event the list's filter matches, not only the rows on screen.
const exportUrl = (format) => `/stream/export?format=${format}${props.shown.filter ? `&f=${encodeURIComponent(props.shown.filter)}` : ''}`;
const exportHint = computed(() => props.shown.matched
    ? `Download all ${props.shown.matched.toLocaleString()} ${props.shown.filter ? 'matching' : 'stored'} events, newest first`
    : 'Nothing to export');

// Rows that arrived since the last refresh flash briefly (row-new in
// app.css). A new filter or another page is a different list, so nothing in
// it counts as new.
const fresh = ref(new Set());
let seen = { key: null, ids: new Set() };
watch(() => props.shown, (stream) => {
    const key = `${stream.filter}|${stream.page}|${stream.per}`;
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

// Click a column to sort the stream; click again to flip it. Sorting is local
// to the rows on screen and survives the live refresh. "Time" is the server's
// own order (newest first), so it stays right across midnight.
const columns = computed(() => [
    { key: 'id', label: 'No.', width: 'w-20' },
    // Wider only while a row from before today carries its date.
    { key: 'at', label: `Time · ${page.props.settings.timezone_label}`, width: props.shown.rows.some((row) => row.at.length > 8) ? 'w-40' : 'w-32' },
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
    const rows = props.shown.rows.map((event, index) => ({ event, index }));

    return rows
        .sort((a, b) => {
            if (key === 'at') return (b.index - a.index) * flip;   // index 0 = newest
            const x = a.event[key], y = b.event[key];
            if (x == null || y == null) return (x == null) - (y == null) || a.index - b.index; // blanks last
            return collator.compare(x, y) * flip || a.index - b.index;
        })
        .map((row) => row.event);
});

const panel = ref(null);
const filterBar = ref(null);

defineExpose({
    focusFilter: () => filterBar.value?.focus(),
    // After a page change the list's first row is on screen: if the panel's
    // top has scrolled off the top of the window, the page comes back up to it.
    bringIntoView() {
        const top = panel.value?.getBoundingClientRect().top;
        if (top !== undefined && top < 0) panel.value.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
    },
});
</script>

<template>
    <!-- A page of rows, no scrollbar of its own: the page scrolls, and
         the panel at least reaches the bottom of the right rail. -->
    <div ref="panel" class="flex flex-1 scroll-mt-3 flex-col border border-grid bg-panel">
        <div class="flex items-center gap-3 border-b border-grid px-4 py-2">
            <h2 class="whitespace-nowrap text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Live event stream</h2>
            <!-- Says when the list isn't following new events. Always takes
                 its space, so the filter bar never shifts when it appears. -->
            <span
                role="status"
                class="w-[4.5rem] shrink-0 border border-amber/50 py-0.5 text-center text-[0.6875rem] uppercase tracking-[0.15em] text-amber"
                :class="hold ? '' : 'invisible'"
                :title="hold?.why"
            >{{ hold?.label ?? 'paused' }}</span>
            <StreamFilterBar ref="filterBar" class="flex-1" :applied="stream.filter" :error="stream.error" @apply="apply" />
            <StreamPager compact :page="shown.page" :pages="shown.pages" class="text-[0.75rem]" @go="go" />
        </div>

        <!-- The filter as removable chips; presets on the right. Always
             shown, so applying a filter never moves the table. -->
        <div class="flex flex-wrap items-center gap-1.5 border-b border-grid px-4 py-1.5 text-[0.75rem]">
            <span v-if="!chips.length" class="text-ink-faint">No filter: everything stored</span>
            <span
                v-for="chip in chips"
                :key="chip.label"
                class="flex min-w-0 items-center gap-1 border border-phosphor/40 bg-phosphor/5 py-0.5 pl-1.5 pr-0.5 text-ink"
            >
                <span class="max-w-[22rem] truncate" :title="chip.label">{{ chip.label }}</span>
                <button
                    type="button"
                    class="px-1 text-ink-faint hover:text-alarm"
                    :aria-label="`Remove ${chip.label}`"
                    :title="`Remove ${chip.label}`"
                    @click="apply(removeChip(shown.filter, chip))"
                >✕</button>
            </span>
            <span class="ml-auto flex flex-wrap items-center gap-1.5">
                <span class="uppercase tracking-[0.1em] text-ink-faint">Quick</span>
                <button
                    v-for="preset in presets"
                    :key="preset.label"
                    type="button"
                    class="border px-1.5 py-0.5"
                    :class="preset.active ? 'border-phosphor/60 bg-phosphor/10 text-phosphor' : 'border-edge text-ink-dim hover:border-phosphor/50 hover:text-phosphor'"
                    :aria-pressed="preset.active"
                    :title="`${preset.active ? 'Remove' : 'Add'}: ${preset.title}`"
                    @click="preset.apply"
                >{{ preset.label }}</button>
            </span>
        </div>

        <div
            class="flex-1"
            @mouseenter="emit('hold')"
            @mouseleave="emit('release')"
        >
            <div
                class="outline-none focus-visible:ring-1 focus-visible:ring-phosphor/40"
                tabindex="0"
                aria-label="Event stream. Up and down arrows move the selection, Page Up and Page Down turn the page, Escape closes the details."
                @keydown.down.prevent="step(1)"
                @keydown.up.prevent="step(-1)"
                @keydown.page-down.prevent="go(shown.page + 1)"
                @keydown.page-up.prevent="go(shown.page - 1)"
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
                                fresh.has(event.id) ? (event.kind === 'exploit' ? 'row-new-exploit' : 'row-new') : '',
                            ]"
                            :aria-selected="selected === event.id"
                            @click="select(event.id)"
                        >
                            <td class="px-3 py-1 tabular-nums text-ink-faint">{{ event.id }}</td>
                            <td class="px-3 py-1 tabular-nums text-ink-faint">{{ event.at }}</td>
                            <td class="px-3 py-1 tabular-nums">
                                <div class="flex min-w-0 items-center justify-between gap-2">
                                    <FilterButton
                                        class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                        :condition="`src == ${event.src_ip}`"
                                        @filter="filter"
                                    >{{ event.src }}</FilterButton>
                                    <DossierLink :ip="event.src_ip" />
                                </div>
                            </td>
                            <td class="truncate px-3 py-1 tabular-nums text-ink-dim" :title="event.dst">{{ event.dst }}</td>
                            <td class="px-3 py-1 text-signal">{{ event.proto }}</td>
                            <td class="truncate px-3 py-1" :class="kindTone[event.kind]" :title="[event.info, meaning('kinds', event.kind)].filter(Boolean).join('\n')">{{ event.info }}</td>
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

        <EventDetails v-if="selected" :id="selected" @close="selected = null" @filter="filter" />

        <!-- Status bar, as in Wireshark: what's shown out of what matches. -->
        <!-- A container, so the legend shows only when the bar itself has
             room (the right rail and the text size both narrow it). -->
        <div class="@container flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-grid px-4 py-1.5 text-[0.75rem] text-ink-faint">
            <span class="min-w-0 truncate tabular-nums">
                {{ firstShown.toLocaleString() }}–{{ lastShown.toLocaleString() }} of
                {{ shown.matched.toLocaleString() }} {{ shown.filter ? 'matching' : 'stored' }}
            </span>
            <span class="hidden items-center gap-3 whitespace-nowrap @min-[60rem]:flex" aria-hidden="true">
                <span v-for="[label, swatch, kind] in legend" :key="label" class="flex items-center gap-1.5" :title="meaning('kinds', kind)">
                    <span class="inline-block h-2 w-2" :class="swatch" />{{ label }}
                </span>
            </span>
            <span class="flex shrink-0 items-center gap-2">
                <span class="uppercase tracking-[0.1em]">Export</span>
                <a
                    v-for="format in ['csv', 'json']"
                    :key="format"
                    :href="shown.matched ? exportUrl(format) : undefined"
                    :aria-disabled="!shown.matched"
                    :aria-label="`Export ${format}`"
                    :title="exportHint"
                    class="border border-edge px-2 py-0.5 uppercase tracking-[0.1em] text-ink-dim"
                    :class="shown.matched ? 'hover:border-phosphor/50 hover:text-phosphor' : 'pointer-events-none opacity-40'"
                >{{ format }} ↓</a>
            </span>
            <span class="flex shrink-0 items-center gap-1" role="group" aria-label="Rows per page">
                <span class="uppercase tracking-[0.1em]">Rows</span>
                <button
                    v-for="per in PER_PAGE"
                    :key="per"
                    type="button"
                    class="border px-1.5 py-0.5 tabular-nums"
                    :class="perPage === per ? 'border-phosphor/60 text-phosphor' : 'border-edge text-ink-dim hover:text-phosphor'"
                    :aria-pressed="perPage === per"
                    @click="perPage !== per && emit('per', per)"
                >{{ per }}</button>
            </span>
            <!-- Right-aligned, so when the bar wraps it sits under Rows. -->
            <StreamPager :page="shown.page" :pages="shown.pages" class="ml-auto" @go="go" />
        </div>
    </div>
</template>
