<script setup>
import { onBeforeUnmount, reactive, ref, watch } from 'vue';
import { Link } from '@inertiajs/vue3';
import { KIND_LABEL as kindLabel, KIND_TONE as kindTone } from '../kinds';
import { countryName } from '../country';

// The selected event, taken apart like Wireshark's packet details: one
// section per layer, each field with "filter" and "exclude" when it maps to
// a display-filter field. Everything here came from an attacker's request,
// so it is only ever shown as text.
const props = defineProps({ id: { type: Number, required: true } });
const emit = defineEmits(['close', 'filter']);

const event = ref(null);
const failed = ref(false);
const raw = ref(false);
// Long sections start folded; the choice sticks while you move between events.
const folded = reactive({ 'Headers, in the order sent': true });

let pending = null;
async function load(id) {
    pending?.abort();
    pending = new AbortController();
    failed.value = false;
    try {
        const response = await fetch(`/events/${id}`, { headers: { Accept: 'application/json' }, signal: pending.signal });
        if (!response.ok) throw new Error(String(response.status));
        event.value = await response.json();
    } catch (error) {
        if (error.name !== 'AbortError') {
            failed.value = true;
            event.value = null;
        }
    }
}
watch(() => props.id, load, { immediate: true });
onBeforeUnmount(() => pending?.abort());

</script>

<template>
    <!-- Shares the stream panel's height with the list (both flex-1), so a
         short list leaves no gap above the details on a tall panel. -->
    <div class="flex min-h-80 flex-1 flex-col border-t border-grid">
        <div class="flex items-center gap-3 border-b border-grid bg-panel-lit px-4 py-1.5 text-[0.75rem]">
            <span class="uppercase tracking-[0.2em] text-ink-dim">Event {{ id }}</span>
            <span v-if="event" class="uppercase tracking-wider" :class="kindTone[event.kind]">{{ kindLabel[event.kind] }}</span>
            <span class="ml-auto flex items-center gap-2">
                <button
                    type="button"
                    class="border border-edge px-2 py-0.5 uppercase tracking-[0.1em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor disabled:opacity-40"
                    :disabled="!event"
                    :aria-pressed="raw"
                    @click="raw = !raw"
                >{{ raw ? 'Fields' : 'Raw' }}</button>
                <Link
                    v-if="event"
                    :href="event.dossier"
                    class="border border-edge px-2 py-0.5 uppercase tracking-[0.1em] text-ink-dim hover:border-phosphor/50 hover:text-phosphor"
                >Dossier ▸</Link>
                <!-- Holds the link's place while the event loads, so Raw doesn't move. -->
                <span v-else aria-disabled="true" class="border border-edge px-2 py-0.5 uppercase tracking-[0.1em] text-ink-dim opacity-40">Dossier ▸</span>
                <button
                    type="button"
                    class="border border-edge px-2 py-0.5 text-ink-dim hover:border-amber/50 hover:text-amber"
                    aria-label="Close the details"
                    @click="emit('close')"
                >✕</button>
            </span>
        </div>

        <div class="min-h-0 flex-1 overflow-y-auto px-4 py-2 text-[0.75rem]">
            <p v-if="failed" class="py-4 text-center text-ink-faint">This event is no longer stored.</p>
            <p v-else-if="!event" class="py-4 text-center text-ink-faint">Loading…</p>

            <pre v-else-if="raw" class="whitespace-pre-wrap break-all text-ink-dim">{{ JSON.stringify(event.raw, null, 2) }}</pre>

            <template v-else>
                <section v-for="section in event.sections" :key="section.title" class="mb-1">
                    <button
                        type="button"
                        class="flex w-full items-center gap-1.5 py-0.5 text-left text-ink hover:text-phosphor"
                        :aria-expanded="!folded[section.title]"
                        @click="folded[section.title] = !folded[section.title]"
                    >
                        <span class="inline-block w-3 text-ink-faint">{{ folded[section.title] ? '▸' : '▾' }}</span>
                        {{ section.title }}
                        <span v-if="folded[section.title]" class="text-ink-faint">({{ section.fields.length }})</span>
                    </button>
                    <table v-if="!folded[section.title]" class="mb-1 ml-4 w-[calc(100%-1rem)]">
                        <tbody>
                            <tr v-for="(field, index) in section.fields" :key="index" class="group align-top hover:bg-panel-lit">
                                <td class="w-44 whitespace-nowrap py-0.5 pr-3 text-ink-faint">{{ field.label }}</td>
                                <td class="whitespace-pre-wrap break-all py-0.5 pr-3 text-ink-dim">{{ field.label === 'Country' ? countryName(field.value) : field.value }}</td>
                                <td class="w-28 whitespace-nowrap py-0.5 text-right">
                                    <template v-if="field.filter">
                                        <button
                                            type="button"
                                            class="text-ink-faint hover:text-phosphor hover:underline group-hover:text-ink-dim"
                                            :title="`Filter: ${field.filter}`"
                                            @click="emit('filter', field.filter, false)"
                                        >filter</button>
                                        <button
                                            type="button"
                                            class="ml-2 text-ink-faint hover:text-amber hover:underline group-hover:text-ink-dim"
                                            :title="`Exclude: !(${field.filter})`"
                                            @click="emit('filter', field.filter, true)"
                                        >exclude</button>
                                    </template>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </section>
            </template>
        </div>
    </div>
</template>
