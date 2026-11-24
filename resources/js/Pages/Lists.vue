<script setup>
import { computed, ref, watch } from 'vue';
import { Head, Link, router, usePage } from '@inertiajs/vue3';
import PageHeader from '../Components/PageHeader.vue';
import SeverityBadge from '../Components/SeverityBadge.vue';

const props = defineProps({ bans: Object, blocklist: Array });

const page = usePage();

const where = (row) => [row.country, row.org].filter(Boolean).join(' · ') || '—';

// Each list's columns: what a click on the heading sorts by.
const COLUMNS = {
    banned: [
        { key: 'ip', label: 'Address', value: (r) => r.ip },
        { key: 'where', label: 'Where', value: where },
        { key: 'why', label: 'Why', value: (r) => [r.severity ?? -1, r.title ?? ''] },
        { key: 'banned', label: 'Banned', zone: true, value: (r) => r.banned_ts },
        { key: 'expires', label: 'Expires', value: (r) => r.expires_ts },
    ],
    blocklist: [
        { key: 'ip', label: 'Address', value: (r) => r.ip },
        { key: 'where', label: 'Where', value: where },
        { key: 'rules', label: 'Rules', value: (r) => r.rules.join(' ') },
        { key: 'alerts', label: 'Alerts', value: (r) => r.alerts },
        { key: 'severity', label: 'Severity', value: (r) => r.severity },
        { key: 'last_seen', label: 'Last seen', zone: true, value: (r) => r.last_seen_ts },
        { key: 'banned', label: 'Banned', value: (r) => (r.banned ? 1 : 0) },
    ],
};
const DEFAULT_SORT = { banned: { key: 'banned', dir: 'desc' }, blocklist: { key: 'last_seen', dir: 'desc' } };
const tabs = Object.keys(COLUMNS);

// The tab, filter and sort live in the URL (?tab=blocklist&q=cn&sort=alerts:desc),
// so a reload or a shared link opens the same view.
const params = new URLSearchParams(window.location.search);
const tab = ref(tabs.includes(params.get('tab')) ? params.get('tab') : 'banned');

function sortFromUrl(name) {
    const [key, dir] = (params.get('sort') ?? '').split(':');
    return name === tab.value && COLUMNS[name].some((c) => c.key === key) && ['asc', 'desc'].includes(dir)
        ? { key, dir }
        : { ...DEFAULT_SORT[name] };
}
const sorts = ref({ banned: sortFromUrl('banned'), blocklist: sortFromUrl('blocklist') });
const queries = ref({ banned: tab.value === 'banned' ? params.get('q') ?? '' : '', blocklist: tab.value === 'blocklist' ? params.get('q') ?? '' : '' });
const onlyBanned = ref(['banned', 'unbanned'].includes(params.get('only')) ? params.get('only') : 'all');   // blocklist only

function syncUrl() {
    const url = new URL(window.location.href);
    const sort = sorts.value[tab.value];
    const isDefault = sort.key === DEFAULT_SORT[tab.value].key && sort.dir === DEFAULT_SORT[tab.value].dir;
    const set = (name, value) => (value ? url.searchParams.set(name, value) : url.searchParams.delete(name));
    set('tab', tab.value);
    set('q', queries.value[tab.value].trim());
    set('sort', isDefault ? '' : `${sort.key}:${sort.dir}`);
    set('only', tab.value === 'blocklist' && onlyBanned.value !== 'all' ? onlyBanned.value : '');
    // Through Inertia, not history.replaceState: Inertia keeps the page's
    // address in its own state, and would go on believing the old one. A
    // client-side visit: nothing is fetched, and this page's state stays.
    router.replace({ url: url.pathname + url.search, preserveState: true, preserveScroll: true });
}
watch([tab, sorts, queries, onlyBanned], syncUrl, { deep: true });

function show(name) {
    tab.value = name;
}

// Click a heading to sort by it; click it again to flip the order. Numbers,
// dates and severities start biggest first, text A to Z.
function sortBy(column) {
    const current = sorts.value[tab.value];
    const numeric = ['alerts', 'severity', 'banned', 'expires', 'last_seen', 'why'].includes(column.key);
    sorts.value[tab.value] = current.key === column.key
        ? { key: column.key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
        : { key: column.key, dir: numeric ? 'desc' : 'asc' };
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
function compare(a, b) {
    if (Array.isArray(a)) {
        for (let i = 0; i < a.length; i++) {
            const c = compare(a[i], b[i]);
            if (c) return c;
        }
        return 0;
    }
    if (typeof a === 'number' && typeof b === 'number') return a - b;
    return collator.compare(String(a ?? ''), String(b ?? ''));
}

// The filter matches any of a row's words: address, country, network, rule,
// reason. Several words must all match ("cn exploit").
const searchText = (row) => [row.ip, row.country, row.org, row.title, row.rule, ...(row.rules ?? [])].filter(Boolean).join(' ').toLowerCase();

function visible(rows, name) {
    const terms = queries.value[name].toLowerCase().split(/\s+/).filter(Boolean);
    const column = COLUMNS[name].find((c) => c.key === sorts.value[name].key);
    const flip = sorts.value[name].dir === 'asc' ? 1 : -1;
    return rows
        .filter((row) => name !== 'blocklist' || onlyBanned.value === 'all' || (onlyBanned.value === 'banned') === row.banned)
        .filter((row) => terms.every((term) => searchText(row).includes(term)))
        .map((row, index) => ({ row, index }))
        .sort((a, b) => compare(column.value(a.row), column.value(b.row)) * flip || a.index - b.index)
        .map(({ row }) => row);
}

const bannedRows = computed(() => visible(props.bans.rows ?? [], 'banned'));
const blocklistRows = computed(() => visible(props.blocklist, 'blocklist'));
const filtered = computed(() => (tab.value === 'banned' ? bannedRows.value.length < (props.bans.rows ?? []).length : blocklistRows.value.length < props.blocklist.length));
const heading = (column) => (column.zone ? `${column.label} · ${page.props.settings.timezone_label}` : column.label);
const ariaSort = (column) => (sorts.value[tab.value].key === column.key ? (sorts.value[tab.value].dir === 'asc' ? 'ascending' : 'descending') : 'none');
</script>

<template>
    <Head title="Lists" />

    <div class="min-h-screen bg-void px-5 py-4">
        <PageHeader class="mb-4" title="LISTS" subtitle="Who is banned, and who is on the blocklist" />

        <nav class="mb-3 flex items-center gap-2" aria-label="Lists">
            <button
                v-for="name in tabs"
                :key="name"
                type="button"
                class="border px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em]"
                :class="tab === name ? 'border-phosphor/60 text-phosphor' : 'border-edge text-ink-dim hover:border-phosphor/50 hover:text-phosphor'"
                :aria-current="tab === name ? 'page' : undefined"
                @click="show(name)"
            >
                {{ name === 'banned' ? 'Banned' : 'Blocklist' }}
                <span class="ml-1 tabular-nums text-ink-faint">{{ name === 'banned' ? (bans.rows ?? []).length : blocklist.length }}</span>
            </button>
        </nav>

        <!-- Banned: fail2ban's live bans -->
        <section v-if="tab === 'banned'">
            <p v-if="!bans.enabled" class="border border-grid bg-panel px-4 py-6 text-[0.8125rem] text-ink-dim">
                The ban feed is off on this server, so fail2ban bans nobody. Turn it on with
                <code class="text-ink">BAN=yes</code> in <code class="text-ink">/etc/bawls/bawls.conf</code> and run the installer again.
            </p>
            <p v-else-if="!bans.as_of" class="border border-grid bg-panel px-4 py-6 text-[0.8125rem] text-ink-dim">
                No ban list yet. A timer copies fail2ban's bans here every minute; check it with
                <code class="text-ink">sudo systemctl status bawls-bans.timer</code>.
            </p>
            <template v-else>
                <!-- Same row as the blocklist's (room for the Download button or a wrapped second line), so switching tabs doesn't move the table. -->
                <div class="mb-2 flex min-h-9 items-center justify-between gap-3">
                    <p class="text-[0.75rem] text-ink-faint">
                        Banned on every port of this server by fail2ban, for exploit attempts. As of {{ bans.as_of }} · refreshed every minute.
                    </p>
                </div>
                <p v-if="bans.stale" class="mb-2 border border-amber/50 px-3 py-2 text-[0.8125rem] text-amber">
                    This copy is more than 5 minutes old, so the timer that refreshes it may have stopped:
                    <code>sudo systemctl status bawls-bans.timer</code>
                </p>
            </template>
        </section>

        <!-- Blocklist: every external address that raised an alert -->
        <section v-else>
            <div class="mb-2 flex min-h-9 items-center justify-between gap-3">
                <p class="text-[0.75rem] text-ink-faint">
                    Every outside address that raised an alert in the last 30 days, for your other firewalls. Your own addresses are left out.
                </p>
                <a href="/blocklist.txt" download class="shrink-0 border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Download .txt</a>
            </div>
        </section>

        <template v-if="tab === 'blocklist' || (bans.enabled && bans.as_of)">
            <!-- Filter, and how many rows it leaves. -->
            <div class="mb-2 flex flex-wrap items-center gap-2 text-[0.8125rem]">
                <div class="relative">
                    <input
                        v-model="queries[tab]"
                        type="search"
                        spellcheck="false"
                        autocomplete="off"
                        aria-label="Filter the list"
                        placeholder="Filter: address, country, network, rule…"
                        class="w-96 border border-edge bg-panel px-2 py-1 pr-7 text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                    >
                    <button
                        v-if="queries[tab]"
                        type="button"
                        class="absolute right-1.5 top-1/2 -translate-y-1/2 px-1 text-ink-faint hover:text-phosphor"
                        aria-label="Clear the filter"
                        @click="queries[tab] = ''"
                    >✕</button>
                </div>
                <span v-if="tab === 'blocklist'" class="flex" role="group" aria-label="Show">
                    <button
                        v-for="[value, label] in [['all', 'All'], ['banned', 'Banned'], ['unbanned', 'Not banned']]"
                        :key="value"
                        type="button"
                        class="border px-2 py-1 text-[0.75rem] uppercase tracking-[0.1em] first:border-r-0 last:border-l-0"
                        :class="onlyBanned === value ? 'border-phosphor/60 bg-phosphor/10 text-phosphor' : 'border-edge text-ink-dim hover:text-phosphor'"
                        :aria-pressed="onlyBanned === value"
                        @click="onlyBanned = value"
                    >{{ label }}</button>
                </span>
                <span class="ml-auto tabular-nums text-ink-faint">
                    <template v-if="filtered">{{ (tab === 'banned' ? bannedRows : blocklistRows).length.toLocaleString() }} of </template>
                    {{ (tab === 'banned' ? (bans.rows ?? []) : blocklist).length.toLocaleString() }}
                </span>
            </div>

            <div class="border border-grid bg-panel">
                <div class="max-h-[75vh] overflow-y-auto">
                    <table class="w-full text-[0.8125rem]">
                        <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                            <tr class="text-left">
                                <th v-for="column in COLUMNS[tab]" :key="column.key" class="p-0 font-normal" :aria-sort="ariaSort(column)">
                                    <button
                                        type="button"
                                        class="flex w-full items-center gap-1 whitespace-nowrap px-3 py-2 text-left hover:text-phosphor"
                                        :class="sorts[tab].key === column.key ? 'text-ink' : ''"
                                        @click="sortBy(column)"
                                    >
                                        {{ heading(column) }}
                                        <!-- Always takes its space, so the heading never shifts. -->
                                        <span class="inline-block w-2 text-[0.625rem]" :class="sorts[tab].key === column.key ? 'text-phosphor' : 'invisible'">
                                            {{ sorts[tab].key === column.key && sorts[tab].dir === 'asc' ? '▲' : '▼' }}
                                        </span>
                                    </button>
                                </th>
                            </tr>
                        </thead>

                        <tbody v-if="tab === 'banned'">
                            <tr v-for="row in bannedRows" :key="row.ip" class="border-t border-grid/60 hover:bg-panel-lit">
                                <!-- An IPv6 ban is a whole block; its dossier is the address in it that raised the alert. -->
                                <td class="px-3 py-1.5 tabular-nums">
                                    <Link v-if="row.address" :href="`/ip/${row.address}`" class="text-ink hover:text-phosphor hover:underline" :title="row.address !== row.ip ? `Dossier of ${row.address}` : undefined">{{ row.ip }}</Link>
                                    <span v-else class="text-ink">{{ row.ip }}</span>
                                </td>
                                <td class="max-w-[16rem] truncate px-3 py-1.5 text-ink-dim" :title="where(row)">{{ where(row) }}</td>
                                <td class="px-3 py-1.5">
                                    <template v-if="row.rule">
                                        <SeverityBadge :severity="row.severity" class="mr-2" />
                                        <span class="text-ink-dim">{{ row.title }}</span>
                                    </template>
                                    <span v-else class="text-ink-faint">no alert on record</span>
                                </td>
                                <td class="px-3 py-1.5 tabular-nums text-ink-faint">{{ row.banned_at }}</td>
                                <td class="px-3 py-1.5 tabular-nums text-ink-dim">
                                    {{ row.expires_at }} <span class="text-ink-faint">· {{ row.expires_in }}</span>
                                </td>
                            </tr>
                            <tr v-if="!bannedRows.length">
                                <td colspan="5" class="px-3 py-8 text-center text-ink-faint">
                                    {{ (bans.rows ?? []).length ? 'Nothing matches this filter.' : 'Nobody is banned right now.' }}
                                </td>
                            </tr>
                        </tbody>

                        <tbody v-else>
                            <tr v-for="row in blocklistRows" :key="row.ip" class="border-t border-grid/60 hover:bg-panel-lit">
                                <td class="px-3 py-1.5 tabular-nums">
                                    <Link :href="`/ip/${row.ip}`" class="text-ink hover:text-phosphor hover:underline">{{ row.ip }}</Link>
                                </td>
                                <td class="max-w-[16rem] truncate px-3 py-1.5 text-ink-dim" :title="where(row)">{{ where(row) }}</td>
                                <td class="px-3 py-1.5">
                                    <span
                                        v-for="rule in row.rules"
                                        :key="rule"
                                        class="mr-1 border border-edge px-1 text-[0.6875rem] uppercase tracking-wider text-ink-dim"
                                    >{{ rule }}</span>
                                </td>
                                <td class="px-3 py-1.5 tabular-nums text-ink-dim">{{ row.alerts }}</td>
                                <td class="px-3 py-1.5"><SeverityBadge :severity="row.severity" /></td>
                                <td class="px-3 py-1.5 tabular-nums text-ink-faint">{{ row.last_seen }}</td>
                                <td class="px-3 py-1.5">
                                    <span v-if="row.banned" class="text-[0.75rem] uppercase tracking-wider text-phosphor">banned</span>
                                    <span v-else class="text-ink-faint">—</span>
                                </td>
                            </tr>
                            <tr v-if="!blocklistRows.length">
                                <td colspan="7" class="px-3 py-8 text-center text-ink-faint">
                                    {{ blocklist.length ? 'Nothing matches this filter.' : 'No alerts in the last 30 days, so the blocklist is empty.' }}
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </template>
    </div>
</template>
