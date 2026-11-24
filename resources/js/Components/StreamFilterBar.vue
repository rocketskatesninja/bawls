<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { recentFilters, rememberFilter } from '../stream';

// The stream's display filter, as in Wireshark: green when it parses, red
// (with the reason) when it doesn't, applied with Enter. Messages and menus
// float over the stream instead of pushing it down.
const props = defineProps({
    applied: { type: String, default: '' },
    error: { type: Object, default: null },
});
const emit = defineEmits(['apply']);

const draft = ref(props.applied);
const state = ref('empty'); // empty | checking | ok | bad | unknown
const message = ref('');
const recent = ref(recentFilters());
const open = ref(null); // null | 'recent' | 'help'
const input = ref(null);
const root = ref(null);

let timer = null;
let pending = null;

// Back to the applied filter (Esc, or a new one arriving). A check still
// waiting for the old text is dropped, so its answer can't paint the bar.
function showApplied() {
    clearTimeout(timer);
    pending?.abort();
    draft.value = props.applied;
    state.value = props.error ? 'bad' : props.applied ? 'ok' : 'empty';
    message.value = props.error?.message ?? '';
}
showApplied();
// Primitives, so a live refresh returning the same filter leaves your typing alone.
watch(() => props.applied, showApplied);
watch(() => props.error?.message, showApplied);

function check() {
    clearTimeout(timer);
    pending?.abort();
    const text = draft.value.trim();
    if (!text) {
        state.value = 'empty';
        message.value = '';
        return;
    }
    state.value = 'checking';
    timer = setTimeout(async () => {
        pending = new AbortController();
        try {
            const response = await fetch(`/stream/check?f=${encodeURIComponent(text)}`, {
                headers: { Accept: 'application/json' },
                signal: pending.signal,
            });
            const body = response.ok ? await response.json() : null;
            if (draft.value.trim() !== text) return;   // typed on (or Esc) meanwhile
            state.value = body === null ? 'unknown' : body.ok ? 'ok' : 'bad';
            message.value = body?.error?.message ?? '';
        } catch (error) {
            if (error.name !== 'AbortError') {
                state.value = 'unknown';
            }
        }
    }, 300);
}

function apply() {
    if (state.value === 'bad') {
        return;
    }
    const text = draft.value.trim();
    rememberFilter(text);
    recent.value = recentFilters();
    open.value = null;
    emit('apply', text);
}

function use(filter) {
    draft.value = filter;
    open.value = null;
    check();
    input.value?.focus();
}

function clear() {
    draft.value = '';
    check();
    emit('apply', '');
}

function toggle(menu) {
    open.value = open.value === menu ? null : menu;
}

function outside(event) {
    if (open.value && !root.value?.contains(event.target)) {
        open.value = null;
    }
}
onMounted(() => document.addEventListener('mousedown', outside));
onBeforeUnmount(() => {
    document.removeEventListener('mousedown', outside);
    clearTimeout(timer);
    pending?.abort();
});

// The overview's "/" shortcut jumps here.
defineExpose({ focus: () => input.value?.focus() });

const tone = {
    ok: 'border-phosphor/60 bg-phosphor/5',
    bad: 'border-alarm/70 bg-alarm/10',
    empty: 'border-edge',
    checking: 'border-edge',
    unknown: 'border-edge',
};

const examples = [
    'sig in {sqli rce traversal cve_probe}',
    'login && !banned',
    'path contains "wp-" && country != US',
    'ufw && dst.port in {22 3389}',
];
const fields = [
    ['Addresses', 'ip src dst', ['src == 203.0.113.9', 'ip == 203.0.113.0/24']],
    ['Ports', 'port src.port dst.port', ['port == 22', 'dst.port in {80 443}']],
    ['Event', 'proto action dir no time', ['action == blocked', 'time >= "2026-11-20 14:00"']],
    ['HTTP', 'site method path query ua http.host referer status sig', ['site == decoy', 'path contains "wp-"']],
    ['Source', 'country asn org', ['country == CN', 'org contains "cloud"']],
    ['Flags', 'http decoy ufw login banned', ['login && !banned']],
];
</script>

<template>
    <div ref="root" class="relative min-w-0">
        <form class="flex items-stretch gap-1.5" @submit.prevent="apply">
            <input
                ref="input"
                v-model="draft"
                type="text"
                spellcheck="false"
                autocomplete="off"
                placeholder="Display filter: src == 203.0.113.9 && sig == sqli"
                aria-label="Display filter"
                :aria-invalid="state === 'bad'"
                class="min-w-0 flex-1 border px-2 py-1 text-[0.8125rem] text-ink outline-none placeholder:text-ink-faint focus:border-phosphor/60"
                :class="tone[state]"
                @input="check"
                @keydown.esc="showApplied"
            />
            <button
                type="button"
                class="border border-edge px-2 text-[0.8125rem] text-ink-dim hover:text-phosphor disabled:opacity-40"
                title="Recent filters"
                aria-label="Recent filters"
                :aria-expanded="open === 'recent'"
                :disabled="!recent.length"
                @click="toggle('recent')"
            >▾</button>
            <button
                type="submit"
                class="border border-edge px-2.5 text-[0.8125rem] uppercase tracking-[0.1em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor disabled:opacity-40"
                :disabled="state === 'bad' || draft.trim() === applied"
            >Apply</button>
            <button
                type="button"
                class="border border-edge px-2.5 text-[0.8125rem] uppercase tracking-[0.1em] text-ink-dim hover:border-amber/50 hover:text-amber disabled:opacity-40"
                :disabled="!draft && !applied"
                @click="clear"
            >Clear</button>
            <button
                type="button"
                class="border border-edge px-2 text-[0.8125rem] text-ink-dim hover:text-phosphor"
                title="Filter syntax"
                aria-label="Filter syntax"
                :aria-expanded="open === 'help'"
                @click="toggle('help')"
            >?</button>
        </form>

        <p
            v-if="state === 'bad' && message && !open"
            role="alert"
            class="absolute left-0 top-full z-20 mt-1 max-w-full border border-alarm/60 bg-panel px-2 py-1 text-[0.75rem] text-alarm shadow-lg"
        >{{ message }}</p>

        <ul
            v-if="open === 'recent'"
            class="absolute left-0 right-0 top-full z-30 mt-1 max-h-72 overflow-y-auto border border-edge bg-panel shadow-lg"
        >
            <li v-for="filter in recent" :key="filter">
                <button type="button" class="block w-full truncate px-3 py-1.5 text-left text-[0.8125rem] text-ink-dim hover:bg-panel-lit hover:text-phosphor" :title="filter" @click="use(filter)">
                    {{ filter }}
                </button>
            </li>
        </ul>

        <div
            v-if="open === 'help'"
            class="absolute right-0 top-full z-30 mt-1 w-[48rem] max-w-[90vw] border border-edge bg-panel p-4 text-[0.75rem] text-ink-dim shadow-lg"
        >
            <p class="mb-2 text-ink">
                Like Wireshark's display filter. Click anything on this page to add it; Alt-click to exclude it.
            </p>
            <table class="mb-3 w-full">
                <tbody>
                    <tr v-for="[group, names, samples] in fields" :key="group" class="align-top">
                        <td class="whitespace-nowrap py-0.5 pr-3 text-ink-faint">{{ group }}</td>
                        <td class="py-0.5 pr-4 text-phosphor">{{ names }}</td>
                        <td class="whitespace-nowrap py-0.5 text-ink-faint">{{ samples.join('  ·  ') }}</td>
                    </tr>
                </tbody>
            </table>
            <p class="mb-1">
                <span class="text-ink">Operators</span>
                <code class="ml-2 text-phosphor">== != contains &lt; &gt; &lt;= &gt;= in {…}</code>
                <span class="mx-2">joined with</span>
                <code class="text-phosphor">&& || ! ( )</code>
            </p>
            <p class="mb-3">
                Wireshark's names work too (ip.src, tcp.dstport, http.request.uri). A comparison only matches
                events that have the field: <code class="text-ink">path != "/"</code> skips firewall events,
                <code class="text-ink">!(path == "/")</code> doesn't.
            </p>
            <p class="mb-1 text-ink">Examples</p>
            <button
                v-for="example in examples"
                :key="example"
                type="button"
                class="mb-1 mr-1 border border-edge px-2 py-0.5 text-left text-phosphor hover:border-phosphor/50"
                @click="use(example)"
            >{{ example }}</button>
        </div>
    </div>
</template>
