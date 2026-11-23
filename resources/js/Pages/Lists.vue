<script setup>
import { ref } from 'vue';
import { Head, Link, usePage } from '@inertiajs/vue3';
import BawlsMark from '../Components/BawlsMark.vue';
import SeverityBadge from '../Components/SeverityBadge.vue';

defineProps({ bans: Object, blocklist: Array });

const page = usePage();

// The open tab lives in the URL (?tab=blocklist), so a reload or a shared
// link opens the same list.
const tabs = ['banned', 'blocklist'];
const fromUrl = new URLSearchParams(window.location.search).get('tab');
const tab = ref(tabs.includes(fromUrl) ? fromUrl : 'banned');

function show(name) {
    tab.value = name;
    const url = new URL(window.location.href);
    url.searchParams.set('tab', name);
    window.history.replaceState(window.history.state, '', url);
}

const where = (row) => [row.country, row.org].filter(Boolean).join(' · ') || '—';
</script>

<template>
    <Head title="Lists" />

    <div class="min-h-screen bg-void px-5 py-4">
        <header class="mb-4 flex items-center justify-between border-b border-grid pb-3">
            <div class="flex items-center gap-3">
                <BawlsMark />
                <div>
                    <h1 class="text-lg font-bold tracking-[0.3em] text-phosphor glow">LISTS</h1>
                    <p class="text-[0.75rem] uppercase tracking-[0.2em] text-ink-faint">Who is banned, and who is on the blocklist</p>
                </div>
            </div>
            <Link href="/" class="border border-edge px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor">◂ Console</Link>
        </header>

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
                <span class="ml-1 tabular-nums text-ink-faint">{{ name === 'banned' ? bans.rows.length : blocklist.length }}</span>
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
                <div class="border border-grid bg-panel">
                    <div class="max-h-[75vh] overflow-y-auto">
                        <table class="w-full text-[0.8125rem]">
                            <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                                <tr class="text-left">
                                    <th class="px-3 py-2 font-normal">Address</th>
                                    <th class="px-3 py-2 font-normal">Where</th>
                                    <th class="px-3 py-2 font-normal">Why</th>
                                    <th class="px-3 py-2 font-normal">Banned · {{ page.props.settings.timezone_label }}</th>
                                    <th class="px-3 py-2 font-normal">Expires</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="row in bans.rows" :key="row.ip" class="border-t border-grid/60 hover:bg-panel-lit">
                                    <td class="px-3 py-1.5 tabular-nums">
                                        <Link :href="`/ip/${row.ip}`" class="text-ink hover:text-phosphor hover:underline">{{ row.ip }}</Link>
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
                                <tr v-if="!bans.rows.length">
                                    <td colspan="5" class="px-3 py-8 text-center text-ink-faint">Nobody is banned right now.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
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
            <div class="border border-grid bg-panel">
                <div class="max-h-[75vh] overflow-y-auto">
                    <table class="w-full text-[0.8125rem]">
                        <thead class="sticky top-0 bg-panel-lit text-ink-faint">
                            <tr class="text-left">
                                <th class="px-3 py-2 font-normal">Address</th>
                                <th class="px-3 py-2 font-normal">Where</th>
                                <th class="px-3 py-2 font-normal">Rules</th>
                                <th class="px-3 py-2 font-normal">Alerts</th>
                                <th class="px-3 py-2 font-normal">Severity</th>
                                <th class="px-3 py-2 font-normal">Last seen · {{ page.props.settings.timezone_label }}</th>
                                <th class="px-3 py-2 font-normal">Banned</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="row in blocklist" :key="row.ip" class="border-t border-grid/60 hover:bg-panel-lit">
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
                            <tr v-if="!blocklist.length">
                                <td colspan="7" class="px-3 py-8 text-center text-ink-faint">No alerts in the last 30 days, so the blocklist is empty.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </section>
    </div>
</template>
