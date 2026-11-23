<script setup>
import { Link } from '@inertiajs/vue3';

// The way into an IP's dossier wherever an address is listed. Clicking the
// address itself adds it to the display filter; this opens the dossier.
// The span stops the click from also selecting the row it sits in (Inertia's
// Link replaces any click listener put on it directly).
defineProps({ ip: { type: String, required: true } });
</script>

<template>
    <span class="shrink-0" @click.stop>
        <Link
            :href="`/ip/${ip}`"
            class="inline-block border border-edge px-1.5 text-[0.6875rem] leading-[1.0625rem] text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
            :title="`Open the dossier for ${ip}`"
            :aria-label="`Open the dossier for ${ip}`"
        >dossier</Link>
    </span>
</template>
