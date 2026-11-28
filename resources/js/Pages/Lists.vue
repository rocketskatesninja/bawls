<script setup>
import { computed, ref, watch } from 'vue';
import { Head, Link, router, usePage } from '@inertiajs/vue3';
import PageHeader from '../Components/PageHeader.vue';
import SeverityBadge from '../Components/SeverityBadge.vue';
import { countryName } from '../country';

// One table: every outside address that raised an alert, and the ban it is
// under when it has one. "Who is banned right now" is the Banned filter.
const props = defineProps({
    bans: Object,   // { enabled, as_of, stale }: the state of the copy of fail2ban's bans
    rows: Array,
});

const page = usePage();

const where = (row) => [countryName(row.country), row.org].filter(Boolean).join(' · ') || '—';

// The columns: what a click on the heading sorts by.
const COLUMNS = [
    { key: 'ip', label: 'Address', value: (r) => r.ip },
    { key: 'where', label: 'Where', value: where },
    { key: 'rules', label: 'Rules', value: (r) => r.rules.join(' ') },
    { key: 'alerts', label: 'Alerts', value: (r) => r.alerts },
    { key: 'severity', label: 'Severity', value: (r) => r.severity ?? -1 },
    { key: 'last_seen', label: 'Last seen', zone: true, value: (r) => r.last_seen_ts },
    { key: 'banned', label: 'Banned until', zone: true, value: (r) => r.ban?.expires_ts ?? 0 },
    { key: 'alert', label: 'Alert', value: (r) => (r.reopen ? 0 : 1) },
];
const NUMERIC = ['alerts', 'severity', 'last_seen', 'banned'];
const DEFAULT_SORT = { key: 'last_seen', dir: 'desc' };
const SHOW = [['all', 'All'], ['banned', 'Banned'], ['unbanned', 'Not banned']];

// "Reopen" puts an address's hidden and dismissed alerts back in the
// overview's Open alerts panel.
const REOPEN_HINT = 'Its alert was hidden or dismissed. Reopen puts it back in Open alerts on the overview.';
const reopening = ref(null);
function reopen(ip) {
    router.post('/alerts/reopen', { ip }, {
        preserveState: true,
        preserveScroll: true,
        onStart: () => (reopening.value = ip),
        onFinish: () => (reopening.value = null),
    });
}

// The filter and sort live in the URL (?only=banned&q=cn&sort=alerts:desc),
// so a reload or a shared link opens the same view. Links from when the page
// had two tabs still land on the right rows.
const params = new URLSearchParams(window.location.search);
const [sortKey, sortDir] = (params.get('sort') ?? '').split(':');
const sort = ref(COLUMNS.some((c) => c.key === sortKey) && ['asc', 'desc'].includes(sortDir) ? { key: sortKey, dir: sortDir } : { ...DEFAULT_SORT });
const query = ref(params.get('q') ?? '');
const only = ref(SHOW.some(([value]) => value === params.get('only')) ? params.get('only') : params.get('tab') === 'banned' ? 'banned' : 'all');

function syncUrl() {
    const url = new URL(window.location.href);
    const isDefault = sort.value.key === DEFAULT_SORT.key && sort.value.dir === DEFAULT_SORT.dir;
    const set = (name, value) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name));
    set('tab', '');
    set('q', query.value.trim());
    set('sort', isDefault ? '' : `${sort.value.key}:${sort.value.dir}`);
    set('only', only.value !== 'all' ? only.value : '');
    // Through Inertia, not history.replaceState: Inertia keeps the page's
    // address in its own state, and would go on believing the old one. A
    // client-side visit: nothing is fetched, and this page's state stays.
    router.replace({ url: url.pathname + url.search, preserveState: true, preserveScroll: true });
}
watch([sort, query, only], syncUrl, { deep: true });

// Click a heading to sort by it; click it again to flip the order. Numbers,
// dates and severities start biggest first, text A to Z.
function sortBy(column) {
    sort.value = sort.value.key === column.key
        ? { key: column.key, dir: sort.value.dir === 'asc' ? 'desc' : 'asc' }
        : { key: column.key, dir: NUMERIC.includes(column.key) ? 'desc' : 'asc' };
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
function compare(a, b) {
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return collator.compare(String(a ?? ''), String(b ?? ''));
}

// The filter matches any of a row's words: address, country, network, rule.
// Several words must all match ("cn exploit").
const searchText = (row) => [row.ip, row.ban?.block, row.country, countryName(row.country), row.org, ...row.rules].filter(Boolean).join(' ').toLowerCase();

const counts = computed(() => {
    const banned = props.rows.filter((row) => row.ban).length;
    return { all: props.rows.length, banned, unbanned: props.rows.length - banned };
});

const shown = computed(() => {
    const terms = query.value.toLowerCase().split(/\s+/).filter(Boolean);
    const column = COLUMNS.find((c) => c.key === sort.value.key);
    const flip = sort.value.dir === 'asc' ? 1 : -1;
    return props.rows
        .filter((row) => only.value === 'all' || (only.value === 'banned') === !!row.ban)
        .filter((row) => terms.every((term) => searchText(row).includes(term)))
        .map((row, index) => ({ row, index }))
        .sort((a, b) => compare(column.value(a.row), column.value(b.row)) * flip || a.index - b.index)
        .map(({ row }) => row);
});

const heading = (column) => (column.zone ? `${column.label} · ${page.props.settings.timezone_label}` : column.label);
const ariaSort = (column) => (sort.value.key === column.key ? (sort.value.dir === 'asc' ? 'ascending' : 'descending') : 'none');
const banTitle = (ban) => `Banned ${ban.banned_at}${ban.block ? `, as part of the block ${ban.block}` : ''}`;
</script>

<template>
    <Head title="Blocklist" />

    <div class="min-h-screen bg-void px-5 py-4">
        <PageHeader class="mb-4" title="BLOCKLIST" subtitle="Every address that raised an alert, and who is banned right now" />

        <div class="mb-2 flex min-h-9 items-center justify-between gap-3">
            <p class="text-[0.75rem] text-ink-faint">
                Every outside address that raised an alert in the last 30 days; your own addresses are left out.
                <template v-if="bans.enabled && bans.as_of">
                    <span class="text-ink-dim">{{ counts.banned.toLocaleString() }} banned</span> by fail2ban right now (as of {{ bans.as_of }}).
                </template>
            </p>
            <a
                href="/blocklist.txt"
                download
                title="The addresses as plain text, one a line, for your other firewalls"
                class="shrink-0 border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
            >Download .txt</a>
        </div>

        <!-- Why nobody shows as banned, when that is the server's doing. -->
        <p v-if="!bans.enabled" class="mb-2 border border-grid bg-panel px-3 py-2 text-[0.8125rem] text-ink-dim">
            The ban feed is off on this server, so fail2ban bans nobody. Turn it on with
            <code class="text-ink">BAN=yes</code> in <code class="text-ink">/etc/bawls/bawls.conf</code> and run the installer again.
        </p>
        <p v-else-if="!bans.as_of" class="mb-2 border border-grid bg-panel px-3 py-2 text-[0.8125rem] text-ink-dim">
            No ban list yet, so nobody shows as banned. A timer copies fail2ban's bans here every minute; check it with
            <code class="text-ink">sudo systemctl status bawls-bans.timer</code>.
        </p>
        <p v-else-if="bans.stale" class="mb-2 border border-amber/50 px-3 py-2 text-[0.8125rem] text-amber">
            The ban list is more than 5 minutes old, so the timer that refreshes it may have stopped:
            <code>sudo systemctl status bawls-bans.timer</code>
        </p>

        <!-- Filter, and how many rows it leaves. -->
        <div class="mb-2 flex flex-wrap items-center gap-2 text-[0.8125rem]">
            <div class="relative">
                <input
                    v-model="query"
                    type="search"
                    spellcheck="false"
                    autocomplete="off"
                    aria-label="Filter the list"
                    placeholder="Filter: address, country, network, rule…"
                    class="w-96 border border-edge bg-panel px-2 py-1 pr-7 text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                >
                <button
                    v-if="query"
                    type="button"
                    class="absolute right-1.5 top-1/2 -translate-y-1/2 px-1 text-ink-faint hover:text-phosphor"
                    aria-label="Clear the filter"
                    @click="query = ''"
                >✕</button>
            </div>
            <span class="flex" role="group" aria-label="Show">
                <button
                    v-for="[value, label] in SHOW"
                    :key="value"
                    type="button"
                    class="border px-2 py-1 text-[0.75rem] uppercase tracking-[0.1em] first:border-r-0 last:border-l-0"
                    :class="only === value ? 'border-phosphor/60 bg-phosphor/10 text-phosphor' : 'border-edge text-ink-dim hover:text-phosphor'"
                    :aria-pressed="only === value"
                    @click="only = value"
                >{{ label }} <span class="tabular-nums opacity-70">{{ counts[value].toLocaleString() }}</span></button>
            </span>
            <span class="ml-auto tabular-nums text-ink-faint">
                <template v-if="shown.length < rows.length">{{ shown.length.toLocaleString() }} of </template>
                {{ rows.length.toLocaleString() }}
            </span>
        </div>

        <div class="border border-grid bg-panel">
            <div class="max-h-[75vh] overflow-y-auto">
                <table class="w-full text-[0.8125rem]">
                    <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                        <tr class="text-left">
                            <th v-for="column in COLUMNS" :key="column.key" class="p-0 font-normal" :aria-sort="ariaSort(column)">
                                <button
                                    type="button"
                                    class="flex w-full items-center gap-1 whitespace-nowrap px-3 py-2 text-left hover:text-phosphor"
                                    :class="sort.key === column.key ? 'text-ink' : ''"
                                    @click="sortBy(column)"
                                >
                                    {{ heading(column) }}
                                    <!-- Always takes its space, so the heading never shifts. -->
                                    <span class="inline-block w-2 text-[0.625rem]" :class="sort.key === column.key ? 'text-phosphor' : 'invisible'">
                                        {{ sort.key === column.key && sort.dir === 'asc' ? '▲' : '▼' }}
                                    </span>
                                </button>
                            </th>
                        </tr>
                    </thead>

                    <tbody>
                        <tr v-for="row in shown" :key="row.ip" class="border-t border-grid/60 hover:bg-panel-lit">
                            <td class="px-3 py-1.5 tabular-nums">
                                <Link v-if="row.dossier" :href="`/ip/${row.ip}`" class="text-ink hover:text-phosphor hover:underline">{{ row.ip }}</Link>
                                <span v-else class="text-ink">{{ row.ip }}</span>
                            </td>
                            <td class="max-w-[16rem] truncate px-3 py-1.5 text-ink-dim" :title="where(row)">{{ where(row) }}</td>
                            <td class="px-3 py-1.5">
                                <span
                                    v-for="rule in row.rules"
                                    :key="rule"
                                    class="mr-1 border border-edge px-1 text-[0.6875rem] uppercase tracking-wider text-ink-dim"
                                >{{ rule }}</span>
                                <span v-if="!row.rules.length" class="text-ink-faint" title="Banned, but its alert is older than 30 days or was never raised">no alert on record</span>
                            </td>
                            <td class="px-3 py-1.5 tabular-nums text-ink-dim">{{ row.alerts || '—' }}</td>
                            <td class="px-3 py-1.5">
                                <SeverityBadge v-if="row.severity !== null" :severity="row.severity" />
                                <span v-else class="text-ink-faint">—</span>
                            </td>
                            <td class="px-3 py-1.5 tabular-nums text-ink-faint">{{ row.last_seen ?? '—' }}</td>
                            <td class="whitespace-nowrap px-3 py-1.5 tabular-nums">
                                <span v-if="row.ban" class="text-phosphor" :title="banTitle(row.ban)">
                                    {{ row.ban.expires_at }} <span class="text-ink-faint">· {{ row.ban.expires_in }}</span>
                                </span>
                                <span v-else class="text-ink-faint" title="Not banned right now">—</span>
                            </td>
                            <td class="px-3 py-1.5 text-[0.75rem]">
                                <button v-if="row.reopen" type="button" class="uppercase tracking-wider text-amber hover:text-phosphor hover:underline disabled:opacity-40" :disabled="reopening === row.ip" :title="REOPEN_HINT" @click="reopen(row.ip)">reopen</button>
                                <span v-else-if="row.rules.length" class="uppercase tracking-wider text-ink-faint" title="Its alert is in Open alerts on the overview">open</span>
                                <span v-else class="text-ink-faint">—</span>
                            </td>
                        </tr>
                        <tr v-if="!shown.length">
                            <td :colspan="COLUMNS.length" class="px-3 py-8 text-center text-ink-faint">
                                {{ rows.length ? 'Nothing matches this filter.' : 'No alerts in the last 30 days and nobody banned, so the list is empty.' }}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</template>
