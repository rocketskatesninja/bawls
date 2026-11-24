<script setup>
import { router, usePage, Link } from '@inertiajs/vue3';
import BawlsMark from '../BawlsMark.vue';
import { clock } from '../../settings';

// The overview's title row: links to the other pages, the live controls, and
// the account corner. It holds no state; the page owns live, sound and the
// refresh.
defineProps({
    live: { type: Boolean, required: true },
    sound: { type: Boolean, required: true },
    lastRefresh: { type: Date, required: true },
});
const emit = defineEmits(['toggle-live', 'toggle-sound', 'refresh', 'keys']);

const page = usePage();
</script>

<template>
    <!-- Header: icon sits inline to the left of the title; every control
         lives on the right of this same row rather than in a second bar. -->
    <header class="mb-4 flex items-center justify-between gap-4 border-b border-grid pb-3">
        <div class="flex items-center gap-3">
            <BawlsMark />
            <div>
                <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">BAWLS</h1>
                <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">
                    Honeypot console
                </p>
            </div>
        </div>

        <div class="flex flex-wrap items-center justify-end gap-x-3 gap-y-2 whitespace-nowrap">
            <Link href="/ip" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">OSINT ▸</Link>
            <Link href="/credentials" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Creds</Link>
            <Link href="/lists" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">Lists</Link>

            <span class="whitespace-nowrap border-l border-grid pl-3 text-[0.8125rem] tabular-nums text-ink-faint">
                {{ clock(lastRefresh, page.props.settings.timezone) }} {{ page.props.settings.timezone_label }}
            </span>
            <button
                class="border px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] transition-colors"
                :class="live
                    ? 'border-phosphor/50 text-phosphor hover:bg-phosphor/10'
                    : 'border-edge text-ink-dim hover:text-ink'"
                @click="emit('toggle-live')"
            >
                <span v-if="live" class="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-phosphor pulse" />
                {{ live ? 'Live' : 'Paused' }}
            </button>
            <button
                type="button"
                class="border p-1.5"
                :class="sound ? 'border-phosphor/50 text-phosphor hover:bg-phosphor/10' : 'border-edge text-ink-dim hover:text-ink'"
                :aria-pressed="sound"
                aria-label="Sound for new alerts"
                :title="sound
                    ? 'Sound on: a chirp when a new alert opens. After a reload it starts once you click or press a key here.'
                    : 'Sound off: click to chirp when a new alert opens'"
                @click="emit('toggle-sound')"
            >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M4 9h4l5-4v14l-5-4H4z" />
                    <path v-if="sound" d="M16.5 8.5a5 5 0 0 1 0 7M19 6a8.5 8.5 0 0 1 0 12" />
                    <path v-else d="M17 9.5l5 5M22 9.5l-5 5" />
                </svg>
            </button>
            <button
                class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:text-ink"
                @click="emit('refresh')"
            >
                Refresh
            </button>
            <div class="flex items-center gap-2 border-l border-grid pl-4">
                <span class="text-[0.8125rem] text-ink-faint">{{ page.props.auth?.user?.name }}</span>
                <button
                    type="button"
                    title="Keyboard shortcuts (?)"
                    aria-label="Keyboard shortcuts"
                    class="border border-edge px-2 py-0.5 text-[0.8125rem] text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
                    @click="emit('keys')"
                >?</button>
                <Link
                    href="/settings"
                    title="Settings"
                    aria-label="Settings"
                    class="border border-edge p-1.5 text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
                >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                        <circle cx="12" cy="12" r="3.2" />
                        <path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1" />
                    </svg>
                </Link>
                <button
                    class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-alarm/50 hover:text-alarm"
                    @click="router.post('/logout')"
                >
                    Sign out
                </button>
            </div>
        </div>
    </header>
</template>
