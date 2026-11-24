<script setup>
import { Link } from '@inertiajs/vue3';
import BawlsMark from './BawlsMark.vue';

// The title row of every page but the overview: the mark and title on the
// left; on the right the page's own controls (the slot), then the way back.
// The bottom margin is the page's to set (class="mb-4").
defineProps({
    title: { type: String, required: true },
    subtitle: { type: String, required: true },
});
</script>

<template>
    <header class="flex items-center justify-between border-b border-grid pb-3">
        <div class="flex items-center gap-3">
            <BawlsMark />
            <div>
                <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">{{ title }}</h1>
                <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">{{ subtitle }}</p>
            </div>
        </div>

        <div class="flex items-center gap-3">
            <slot />
            <Link href="/" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">◂ Console</Link>
        </div>
    </header>
</template>
