<script setup>
import FilterButton from '../FilterButton.vue';

// What the signatures missed this week (App\\Services\\ProbeDigest). Each row
// carries the stream filter that shows its requests.
defineProps({ digest: { type: Object, required: true } }); // { days, hits, sources, rows: [{ method, path, hits, sources, last_seen, query, queries, explain, filter }] }
const emit = defineEmits(['filter']);
const filter = (condition, exclude) => emit('filter', condition, exclude);
</script>

<template>
    <section class="mt-3 border border-grid bg-panel">
        <div class="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Unrecognised probes · {{ digest.days }} days</h2>
            <span class="text-[0.75rem] text-ink-faint">
                {{ digest.hits.toLocaleString() }} requests from {{ digest.sources.toLocaleString() }} addresses matched no attack pattern
            </span>
        </div>
        <table class="w-full table-fixed text-[0.8125rem]">
            <thead class="text-left text-ink-faint">
                <tr>
                    <th class="w-[30%] px-4 py-1.5 font-normal">Request</th>
                    <th class="px-3 py-1.5 font-normal">What it is</th>
                    <th class="w-28 px-3 py-1.5 text-right font-normal">Addresses</th>
                    <th class="w-28 px-3 py-1.5 text-right font-normal">Requests</th>
                    <th class="w-36 px-4 py-1.5 text-right font-normal">Last seen</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="row in digest.rows" :key="`${row.method} ${row.path}`" class="border-t border-grid/60 align-top">
                    <td class="overflow-hidden px-4 py-1.5">
                        <div class="flex min-w-0 items-baseline gap-2">
                            <span v-if="row.method !== 'GET'" class="shrink-0 border border-amber/50 px-1 text-[0.6875rem] text-amber">{{ row.method }}</span>
                            <FilterButton
                                class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                :condition="row.filter" :lines="[row.path]"
                                @filter="filter"
                            >{{ row.path }}</FilterButton>
                        </div>
                        <div v-if="row.query" class="truncate text-[0.75rem] text-ink-faint" :title="row.query">
                            ?{{ row.query }}<template v-if="row.queries > 1"> · {{ row.queries - 1 }} other {{ row.queries === 2 ? 'query' : 'queries' }}</template>
                        </div>
                    </td>
                    <!-- What the probe is after (App\Services\ProbeCatalog); a guess from the request's shape is marked as one. -->
                    <td class="px-3 py-1.5">
                        <template v-if="row.explain">
                            <div class="flex items-baseline gap-2">
                                <span class="text-ink">{{ row.explain.title }}</span>
                                <span
                                    v-if="!row.explain.known"
                                    class="shrink-0 border border-amber/50 px-1 text-[0.6875rem] uppercase tracking-[0.1em] text-amber"
                                    title="Not in the catalog: a best guess from the request's shape"
                                >guess</span>
                            </div>
                            <p class="text-balance text-[0.75rem] leading-snug text-ink-dim">{{ row.explain.text }}</p>
                        </template>
                    </td>
                    <td class="px-3 py-1.5 text-right tabular-nums text-phosphor">{{ row.sources.toLocaleString() }}</td>
                    <td class="px-3 py-1.5 text-right tabular-nums text-ink-dim">{{ row.hits.toLocaleString() }}</td>
                    <td class="whitespace-nowrap px-4 py-1.5 text-right text-ink-faint">{{ row.last_seen }}</td>
                </tr>
                <tr v-if="!digest.rows.length">
                    <td colspan="5" class="px-4 py-4 text-center text-ink-faint">Nothing digest this week.</td>
                </tr>
            </tbody>
        </table>
        <p class="text-balance border-t border-grid px-4 py-2 text-[0.75rem] text-ink-faint">
            Decoy requests no attack pattern caught, with ordinary page views left out: unknown paths, query strings and unusual methods.
            Click one to see its requests in the stream (Alt-click excludes them). If it's an attack, its pattern can be added to the sensor's list so it's banned next time.
        </p>
    </section>
</template>
