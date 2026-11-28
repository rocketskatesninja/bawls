<script setup>
import { Head, Link, usePage } from '@inertiajs/vue3';
import PageHeader from '../Components/PageHeader.vue';

defineProps({
    attempts: Array,
    // Passwords tried more than once, most first: [{ password, attempts, addresses }].
    mostTried: Array,
});

const page = usePage();

// A masked password is one not on the common-password list: possibly someone's
// real secret, so the sensor kept only its length and a keyed fingerprint
// ("[masked:14 chars #a1b2c3d4e5f6]"; older ones have no fingerprint). A
// shown one is a dictionary guess worth studying.
const MASKED = /^\[masked:(\d+) chars(?: #([0-9a-f]+))?\]$/;

function masked(pw) {
    return typeof pw === 'string' && MASKED.test(pw);
}

/** "masked · 14 chars · #a1b2c3", or the password itself. */
function show(pw) {
    const m = typeof pw === 'string' ? pw.match(MASKED) : null;
    if (!m) return pw ?? '—';
    return `masked · ${m[1]} chars${m[2] ? ` · #${m[2].slice(0, 6)}` : ''}`;
}

const MASKED_HINT = 'Not on the common-password list, so never stored. The # is a keyed fingerprint: '
    + 'the same password gets the same one, so repeats show without the text.';

function triedText(tried) {
    return `×${tried.attempts} · ${tried.addresses} address${tried.addresses === 1 ? '' : 'es'}`;
}
</script>

<template>
    <Head title="Credentials" />

    <div class="min-h-screen bg-void px-5 py-4">
        <PageHeader class="mb-4" title="CREDENTIALS TRIED" subtitle="What attackers sprayed at the fake logins" />

        <!-- The passwords bots keep coming back to, masked ones by fingerprint. -->
        <div v-if="mostTried.length" class="mb-3 flex flex-wrap items-baseline gap-x-2 gap-y-1.5 border border-grid bg-panel px-4 py-2.5 text-[0.8125rem]">
            <span class="mr-1 text-[0.75rem] uppercase tracking-[0.2em] text-ink-dim">Most tried</span>
            <span
                v-for="p in mostTried"
                :key="p.password"
                class="border border-edge px-1.5 py-0.5"
                :title="masked(p.password) ? MASKED_HINT : `Tried ${p.attempts} times by ${p.addresses} address${p.addresses === 1 ? '' : 'es'}`"
            >
                <span :class="masked(p.password) ? 'italic text-ink-faint' : 'text-signal'">{{ show(p.password) }}</span>
                <span class="ml-1.5 tabular-nums text-amber">{{ triedText(p) }}</span>
            </span>
        </div>

        <div class="border border-grid bg-panel">
            <div class="max-h-[80vh] overflow-y-auto">
                <table class="w-full text-[0.8125rem]">
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
                                <span v-if="a.attack" class="ml-2 border border-alarm/50 px-1 text-[0.6875rem] uppercase tracking-wider text-alarm">{{ a.attack }}</span>
                            </td>
                            <td class="px-3 py-1.5 text-amber">{{ a.username ?? '—' }}</td>
                            <td class="px-3 py-1.5">
                                <span :class="masked(a.password) ? 'text-ink-faint italic' : 'text-signal'" :title="masked(a.password) ? MASKED_HINT : null">{{ show(a.password) }}</span>
                                <span v-if="a.tried" class="ml-2 text-[0.75rem] tabular-nums text-amber" :title="`This password was tried ${a.tried.attempts} times by ${a.tried.addresses} address${a.tried.addresses === 1 ? '' : 'es'}`">{{ triedText(a.tried) }}</span>
                            </td>
                        </tr>
                        <tr v-if="!attempts.length">
                            <td colspan="5" class="px-3 py-8 text-center text-ink-faint">No login attempts captured yet.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <p class="mt-3 text-[0.75rem] text-ink-faint">
            Shown passwords are on a list of about 166,000 published common passwords, kept as dictionary data. Anything
            else might be someone's real password, so only its length and a fingerprint were kept: enough to count
            repeats, never the text.
        </p>
    </div>
</template>
