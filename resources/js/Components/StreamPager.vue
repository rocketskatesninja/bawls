<script setup>
import { computed } from 'vue';

// The event stream's pages. Compact ("‹ 3 / 40 ›") for the panel's header;
// full ("« ‹ 1 … 4 5 6 … 40 › »") for its status bar.
const props = defineProps({
    page: { type: Number, required: true },
    pages: { type: Number, required: true },
    compact: { type: Boolean, default: false },
});
const emit = defineEmits(['go']);

const numbers = computed(() => {
    const { page, pages } = props;
    const around = [page - 1, page, page + 1].filter((p) => p > 1 && p < pages);
    return [1, ...(around[0] > 2 ? ['…'] : []), ...around, ...(around.at(-1) < pages - 1 ? ['…'] : []), ...(pages > 1 ? [pages] : [])];
});

const arrow = 'px-1.5 py-0.5 text-ink-dim hover:text-phosphor disabled:opacity-30 disabled:hover:text-ink-dim';
</script>

<template>
    <nav class="flex shrink-0 items-center gap-0.5 tabular-nums" :aria-label="compact ? 'Pages (top)' : 'Pages'">
        <button v-if="!compact" type="button" :class="arrow" :disabled="page <= 1" aria-label="First page" title="First page" @click="emit('go', 1)">«</button>
        <button type="button" :class="arrow" :disabled="page <= 1" aria-label="Previous page" title="Previous page (Page Up)" @click="emit('go', page - 1)">‹</button>
        <span v-if="compact" class="px-1 text-ink-faint">{{ page.toLocaleString() }} / {{ pages.toLocaleString() }}</span>
        <template v-else v-for="(p, i) in numbers" :key="`${p}-${i}`">
            <span v-if="p === '…'" class="px-0.5 text-ink-faint">…</span>
            <button
                v-else
                type="button"
                class="min-w-[1.5rem] border px-1 py-0.5"
                :class="p === page ? 'border-phosphor/60 text-phosphor' : 'border-transparent text-ink-dim hover:border-edge hover:text-phosphor'"
                :aria-current="p === page ? 'page' : undefined"
                :aria-label="`Page ${p}`"
                @click="emit('go', p)"
            >{{ p.toLocaleString() }}</button>
        </template>
        <button type="button" :class="arrow" :disabled="page >= pages" aria-label="Next page" title="Next page (Page Down)" @click="emit('go', page + 1)">›</button>
        <button v-if="!compact" type="button" :class="arrow" :disabled="page >= pages" aria-label="Last page" title="Last page" @click="emit('go', pages)">»</button>
    </nav>
</template>
