<script setup>
import { Head, Link, usePage } from '@inertiajs/vue3';
import BawlsMark from '../Components/BawlsMark.vue';

defineProps({ attempts: Array });

const page = usePage();

// A masked password (the sensor stores "[masked:N chars]" for anything not on
// the common-password list) is a real secret we chose not to keep; a shown one
// is a dictionary guess worth studying.
function masked(pw) {
    return typeof pw === 'string' && pw.startsWith('[masked:');
}
</script>

<template>
    <Head title="Credentials" />

    <div class="min-h-screen bg-void px-5 py-4">
        <header class="mb-4 flex items-center justify-between border-b border-grid pb-3">
            <div class="flex items-center gap-3">
                <BawlsMark />
                <div>
                    <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">CREDENTIALS TRIED</h1>
                    <p class="text-[12px] uppercase tracking-[0.2em] text-ink-faint">What attackers sprayed at the fake logins</p>
                </div>
            </div>
            <Link href="/" class="border border-edge px-3 py-1 text-[13px] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">◂ Console</Link>
        </header>

        <div class="border border-grid bg-panel">
            <div class="max-h-[80vh] overflow-y-auto">
                <table class="w-full text-[13px]">
                    <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                        <tr class="text-left">
                            <th class="px-3 py-2 font-normal">Time · {{ page.props.settings.timezone_label }}</th>
                            <th class="px-3 py-2 font-normal">Source</th>
                            <th class="px-3 py-2 font-normal">Path</th>
                            <th class="px-3 py-2 font-normal">Username</th>
                            <th class="px-3 py-2 font-normal">Password</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="(a, i) in attempts" :key="i" class="border-t border-grid/60 hover:bg-panel-lit">
                            <td class="px-3 py-1.5 tabular-nums text-ink-faint">{{ a.at }}</td>
                            <td class="px-3 py-1.5 tabular-nums">
                                <Link :href="`/ip/${a.ip}`" class="text-ink hover:text-phosphor hover:underline">{{ a.ip }}</Link>
                            </td>
                            <td class="px-3 py-1.5 text-ink-dim">
                                {{ a.path }}
                                <span v-if="a.attack" class="ml-2 border border-alarm/50 px-1 text-[11px] uppercase tracking-wider text-alarm">{{ a.attack }}</span>
                            </td>
                            <td class="px-3 py-1.5 text-amber">{{ a.username ?? '—' }}</td>
                            <td class="px-3 py-1.5" :class="masked(a.password) ? 'text-ink-faint italic' : 'text-signal'">{{ a.password ?? '—' }}</td>
                        </tr>
                        <tr v-if="!attempts.length">
                            <td colspan="5" class="px-3 py-8 text-center text-ink-faint">No login attempts captured yet.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <p class="mt-3 text-[12px] text-ink-faint">
            Shown passwords are common-list guesses kept as dictionary data; anything not on the list was reduced to its
            length and never stored.
        </p>
    </div>
</template>
