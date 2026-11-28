<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Head, useForm, usePage } from '@inertiajs/vue3';
import PageHeader from '../Components/PageHeader.vue';
import { applyAccent, applyTextSize, clock, contrast } from '../settings';

const props = defineProps({
    values: Object,
    defaults: Object,
    zones: Object,       // { region: [{ id, label, offset }] }
    minContrast: Number,
    textSizes: Array,    // [{ value: '115', label: 'Large' }]
});

const page = usePage();
const form = useForm({ ...props.values });

function save() {
    form.put('/settings', {
        preserveScroll: true,
        onSuccess: () => form.defaults(),
    });
}

// --- time zone --------------------------------------------------------------

const offsets = computed(() => {
    const map = { UTC: '+00:00' };
    for (const zones of Object.values(props.zones)) {
        for (const z of zones) map[z.id] = z.offset;
    }
    return map;
});

// The browser's own zone, offered as a one-click choice when PHP knows it
// (a browser can report an old alias such as Asia/Calcutta).
const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const browserZoneKnown = computed(() => browserZone in offsets.value);

const now = ref(new Date());
let ticker = null;
onMounted(() => (ticker = setInterval(() => (now.value = new Date()), 1000)));

const zoneName = computed(() => {
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: form.timezone, timeZoneName: 'short' })
        .formatToParts(now.value);
    return parts.find((p) => p.type === 'timeZoneName')?.value ?? form.timezone;
});

// --- accent -----------------------------------------------------------------

// Bright enough for text on black, and clear of amber and red, which the
// console keeps for "suspicious" and "act now".
const presets = [
    { name: 'Phosphor', hex: '#39ff8b' },
    { name: 'Ice', hex: '#8fe3ff' },
    { name: 'Violet', hex: '#b18cff' },
    { name: 'Magenta', hex: '#ff5fd2' },
    { name: 'Gold', hex: '#ffd447' },
    { name: 'Mono', hex: '#e6ede9' },
];

const validHex = computed(() => /^#[0-9a-fA-F]{6}$/.test(form.accent));
const ratio = computed(() => (validHex.value ? contrast(form.accent) : 0));
const readable = computed(() => ratio.value >= props.minContrast);
const canSave = computed(() => form.isDirty && validHex.value && readable.value && !form.processing);

// Preview the accent on the whole page while choosing; leaving without saving
// puts the saved one back.
watch(() => form.accent, (hex) => {
    if (/^#[0-9a-fA-F]{6}$/.test(hex)) applyAccent(hex.toLowerCase());
});

// --- text size --------------------------------------------------------------

// Previewed on the whole page too, like the accent.
watch(() => form.text_size, applyTextSize);

onUnmounted(() => {
    clearInterval(ticker);
    const saved = page.props.settings;
    if (saved) {
        applyAccent(saved.accent, saved.accent_dim);
        applyTextSize(saved.text_size);
    }
});

const sampleBars = [3, 5, 4, 7, 6, 9, 5, 8, 11, 7, 10, 6];
</script>

<template>
    <Head title="Settings" />

    <div class="min-h-screen bg-void px-5 py-4">
        <PageHeader class="mb-4" title="SETTINGS" subtitle="How the console looks">
            <!-- Holds its space, so the buttons never shift. -->
            <span class="w-14 text-right text-[0.8125rem] uppercase tracking-[0.15em] text-phosphor" :class="form.recentlySuccessful ? '' : 'invisible'">Saved</span>
            <button
                type="submit"
                form="settings-form"
                class="border px-3 py-1 text-[0.8125rem] uppercase tracking-[0.15em] transition-colors disabled:cursor-not-allowed"
                :class="canSave
                    ? 'border-phosphor/60 text-phosphor hover:bg-phosphor/10'
                    : 'border-edge text-ink-faint'"
                :disabled="!canSave"
            >
                Save
            </button>
        </PageHeader>

        <form id="settings-form" class="grid max-w-6xl gap-3 lg:grid-cols-2" @submit.prevent="canSave && save()">
            <!-- Time zone -->
            <section class="border border-grid bg-panel">
                <h2 class="border-b border-grid px-4 py-2 text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Time zone</h2>
                <div class="space-y-4 p-4">
                    <p class="text-[0.8125rem] text-ink-dim">
                        Every time in the console is shown in this zone. Events are stored in UTC either way,
                        so changing it never touches your data.
                    </p>

                    <div class="flex flex-wrap items-center gap-3">
                        <select
                            v-model="form.timezone"
                            aria-label="Time zone"
                            class="w-80 border border-edge bg-void px-2 py-1 text-[0.8125rem] text-ink outline-none focus:border-phosphor/60"
                        >
                            <option value="UTC">UTC · +00:00</option>
                            <optgroup v-for="(list, region) in zones" :key="region" :label="region">
                                <option v-for="z in list" :key="z.id" :value="z.id">{{ z.label }} · {{ z.offset }}</option>
                            </optgroup>
                        </select>
                        <button
                            type="button"
                            class="border border-edge px-3 py-1 text-[0.8125rem] text-ink-dim hover:border-phosphor/50 hover:text-phosphor disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-edge disabled:hover:text-ink-dim"
                            :disabled="!browserZoneKnown || form.timezone === browserZone"
                            :title="browserZoneKnown ? '' : `Your browser reports ${browserZone}, which isn't in the list`"
                            @click="form.timezone = browserZone"
                        >
                            Use this browser's · {{ browserZone }}
                        </button>
                    </div>
                    <p v-if="form.errors.timezone" class="text-[0.8125rem] text-alarm">{{ form.errors.timezone }}</p>

                    <!-- What the console's clock will read -->
                    <div class="flex items-end gap-4 border border-grid bg-void px-4 py-3">
                        <span class="text-4xl font-bold tabular-nums text-phosphor glow">{{ clock(now, form.timezone) }}</span>
                        <span class="pb-1 text-[0.8125rem] text-ink-dim">
                            {{ zoneName }} <span class="text-ink-faint">· UTC{{ offsets[form.timezone] }}</span>
                        </span>
                    </div>
                </div>
            </section>

            <!-- Accent -->
            <section class="border border-grid bg-panel">
                <h2 class="border-b border-grid px-4 py-2 text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Accent colour</h2>
                <div class="space-y-4 p-4">
                    <p class="text-[0.8125rem] text-ink-dim">
                        The console's main colour: headings, the live dot, normal traffic.
                        Amber and red stay reserved for suspicious and act-now.
                    </p>

                    <div class="flex flex-wrap gap-2" role="radiogroup" aria-label="Accent presets">
                        <button
                            v-for="p in presets"
                            :key="p.hex"
                            type="button"
                            role="radio"
                            :aria-checked="form.accent.toLowerCase() === p.hex"
                            class="flex w-20 flex-col items-center gap-1.5 border px-2 py-2 text-[0.75rem] uppercase tracking-[0.1em]"
                            :class="form.accent.toLowerCase() === p.hex ? 'border-ink text-ink' : 'border-edge text-ink-faint hover:text-ink-dim'"
                            @click="form.accent = p.hex"
                        >
                            <span class="block h-6 w-full" :style="{ background: p.hex, boxShadow: `0 0 12px -2px ${p.hex}` }" />
                            {{ p.name }}
                        </button>
                    </div>

                    <div class="flex flex-wrap items-center gap-3">
                        <label class="text-[0.8125rem] text-ink-faint" for="accent-hex">Custom</label>
                        <input
                            type="color"
                            aria-label="Pick a custom accent"
                            class="h-8 w-12 cursor-pointer border border-edge bg-void p-0.5"
                            :value="validHex ? form.accent : '#000000'"
                            @input="form.accent = $event.target.value"
                        />
                        <input
                            id="accent-hex"
                            v-model.trim="form.accent"
                            type="text"
                            maxlength="7"
                            spellcheck="false"
                            class="w-24 border border-edge bg-void px-2 py-1 text-[0.8125rem] lowercase tabular-nums text-ink outline-none focus:border-phosphor/60"
                        />
                        <span class="text-[0.8125rem] tabular-nums" :class="readable ? 'text-ink-faint' : 'text-alarm'">
                            {{ validHex ? `contrast ${ratio.toFixed(1)}:1` : 'not a colour yet' }}
                            <template v-if="validHex && !readable"> · too dark to read on black</template>
                        </span>
                    </div>
                    <p v-if="form.errors.accent" class="text-[0.8125rem] text-alarm">{{ form.errors.accent }}</p>

                    <!-- A slice of the console in the chosen colour -->
                    <div class="flex items-center gap-5 border border-grid bg-void px-4 py-3 glow-box">
                        <span class="text-lg font-bold tracking-[0.3em] text-phosphor glow">BAWLS</span>
                        <span class="border border-phosphor/50 px-2 py-0.5 text-[0.75rem] uppercase tracking-[0.15em] text-phosphor">
                            <span class="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-phosphor pulse" />Live
                        </span>
                        <span class="text-[0.8125rem] uppercase text-phosphor">allowed</span>
                        <div class="ml-auto flex h-8 items-end gap-0.5" aria-hidden="true">
                            <span v-for="(h, i) in sampleBars" :key="i" class="w-1.5 bg-phosphor" :style="{ height: `${h * 8}%` }" />
                        </div>
                    </div>

                    <button
                        type="button"
                        class="text-[0.75rem] uppercase tracking-[0.15em] text-ink-faint hover:text-ink-dim disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:text-ink-faint"
                        :disabled="form.accent.toLowerCase() === defaults.accent"
                        @click="form.accent = defaults.accent"
                    >
                        Back to phosphor green
                    </button>
                </div>
            </section>

            <!-- Text size -->
            <section class="border border-grid bg-panel">
                <h2 class="border-b border-grid px-4 py-2 text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Text size</h2>
                <div class="space-y-4 p-4">
                    <p class="text-[0.8125rem] text-ink-dim">
                        Makes the whole console bigger: text, tables, buttons and the space between them.
                        It's saved with the console, so it applies on every computer you sign in from.
                    </p>

                    <div class="flex flex-wrap gap-2" role="radiogroup" aria-label="Text size">
                        <button
                            v-for="size in textSizes"
                            :key="size.value"
                            type="button"
                            role="radio"
                            :aria-checked="form.text_size === size.value"
                            class="flex w-28 flex-col items-center gap-1 border px-2 py-2 uppercase tracking-[0.1em]"
                            :class="form.text_size === size.value ? 'border-ink text-ink' : 'border-edge text-ink-faint hover:text-ink-dim'"
                            @click="form.text_size = size.value"
                        >
                            <!-- Each sample is drawn at its own size, so the choice shows what it does. -->
                            <span class="font-bold normal-case leading-none" :style="{ fontSize: `${1.25 * size.value / 100}em` }">Aa</span>
                            <span class="text-[0.75rem]">{{ size.label }}</span>
                            <span class="text-[0.75rem] tabular-nums text-ink-faint">{{ size.value }}%</span>
                        </button>
                    </div>
                    <p v-if="form.errors.text_size" class="text-[0.8125rem] text-alarm">{{ form.errors.text_size }}</p>
                </div>
            </section>
        </form>
    </div>
</template>
