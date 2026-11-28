<script setup>
import DossierLink from '../DossierLink.vue';
import FilterButton from '../FilterButton.vue';

// The addresses behind the most events in the last 24 hours.
defineProps({ sources: { type: Array, required: true } }); // [{ ip, hits, ports }]
const emit = defineEmits(['filter']);
const filter = (condition, exclude) => emit('filter', condition, exclude);
</script>

<template>
    <div class="border border-grid bg-panel">
        <div class="border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Top sources · 24h</h2>
        </div>
        <table class="w-full text-[0.8125rem]">
            <thead v-if="sources.length" class="text-left text-ink-faint">
                <tr>
                    <th class="px-4 py-1.5 font-normal">Address</th>
                    <th class="px-2 py-1.5 text-right font-normal" title="How many different ports on your server it tried">Ports</th>
                    <th class="px-4 py-1.5 text-right font-normal" title="Requests and blocked connections">Hits</th>
                </tr>
            </thead>
            <tbody>
                <tr v-for="source in sources" :key="source.ip" class="border-t border-grid/60">
                    <td class="w-full max-w-0 px-4 py-1 tabular-nums">
                        <div class="flex min-w-0 items-center justify-between gap-2">
                            <FilterButton
                                class="min-w-0 truncate text-left text-ink hover:text-phosphor hover:underline"
                                :condition="`src == ${source.ip}`"
                                @filter="filter"
                            >{{ source.ip }}</FilterButton>
                            <DossierLink :ip="source.ip" />
                        </div>
                    </td>
                    <td class="px-2 py-1 text-right tabular-nums text-ink-dim">{{ source.ports }}</td>
                    <td class="px-4 py-1 text-right tabular-nums text-phosphor">
                        {{ source.hits.toLocaleString() }}
                    </td>
                </tr>
                <tr v-if="!sources.length">
                    <td class="px-4 py-4 text-center text-ink-faint">No traffic recorded.</td>
                </tr>
            </tbody>
        </table>
    </div>
</template>
