<script setup>
import FilterButton from '../FilterButton.vue';
import { useMeaning } from '../../glossary';
import { quote } from '../../stream';
import { countryName } from '../../country';

// Three small panels on what the decoy drew in the last 24 hours: the paths
// probed most, the mix of signatures, and where the sources sit.
defineProps({ aggregates: { type: Object, required: true } }); // { paths, signatures, countries }
const emit = defineEmits(['filter']);
const filter = (condition, exclude) => emit('filter', condition, exclude);

const meaning = useMeaning();
</script>

<template>
    <!-- What the decoy is drawing · 24h -->
    <div class="border border-grid bg-panel">
        <div class="border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Top probed paths · 24h</h2>
        </div>
        <table class="w-full text-[0.8125rem]">
            <tbody>
                <tr v-for="p in aggregates.paths" :key="p.path" class="border-t border-grid/60">
                    <!-- w-full + max-w-0 together: max-width:0 alone lets Firefox
                         collapse this column to 0px (the paths vanished). -->
                    <td class="w-full max-w-0 truncate px-4 py-1">
                        <FilterButton
                            class="max-w-full truncate text-left text-ink-dim hover:text-phosphor hover:underline"
                            :condition="`path == ${quote(p.path)}`" :lines="[p.path]"
                            @filter="filter"
                        >{{ p.path }}</FilterButton>
                    </td>
                    <td class="whitespace-nowrap px-4 py-1 text-right tabular-nums text-phosphor">{{ p.hits.toLocaleString() }}</td>
                </tr>
                <tr v-if="!aggregates.paths.length"><td class="px-4 py-4 text-center text-ink-faint">No decoy hits.</td></tr>
            </tbody>
        </table>
    </div>

    <div class="grid grid-cols-2 gap-3">
        <div class="border border-grid bg-panel">
            <div class="border-b border-grid px-4 py-2">
                <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Signatures</h2>
            </div>
            <table class="w-full text-[0.8125rem]">
                <tbody>
                    <tr v-for="s in aggregates.signatures" :key="s.signature" class="border-t border-grid/60">
                        <td class="px-3 py-1">
                            <FilterButton
                                class="uppercase tracking-wider hover:underline"
                                :class="s.signature === 'benign' ? 'text-ink-faint hover:text-ink' : 'text-amber hover:text-phosphor'"
                                :condition="`sig == ${quote(s.signature)}`" :lines="[meaning('signatures', s.signature)]"
                                @filter="filter"
                            >{{ s.signature }}</FilterButton>
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
                            <FilterButton
                                class="hover:text-phosphor hover:underline"
                                :condition="`country == ${quote(c.country)}`"
                                @filter="filter"
                            >{{ countryName(c.country) }}</FilterButton>
                        </td>
                        <td class="px-3 py-1 text-right tabular-nums text-phosphor">{{ c.n }}</td>
                    </tr>
                    <tr v-if="!aggregates.countries.length"><td class="px-3 py-3 text-center text-ink-faint">no geo yet</td></tr>
                </tbody>
            </table>
        </div>
    </div>
</template>
