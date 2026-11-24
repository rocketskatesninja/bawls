<script setup>
import { onUnmounted, ref, watch } from 'vue';
import { router, Link } from '@inertiajs/vue3';
import FilterButton from '../FilterButton.vue';
import SeverityBadge from '../SeverityBadge.vue';
import { useMeaning } from '../../glossary';
import { newIdTracker } from '../../motion';

// Open alerts. One that opened since the last refresh arrives loudly: a red
// flash on its row and three red pulses of the panel's border (alert-in and
// alerts-flash in app.css), and the page is told (`arrived`) so it can chirp
// and mark the tab. Each stays marked NEW (red edge, pulsing tag) until you
// point at it, so one that came in while you looked away is still obvious.
// One whose address was just banned gets its BANNED tag stamped on.
const props = defineProps({ alerts: { type: Array, required: true } });
const emit = defineEmits(['filter', 'arrived']);
const filter = (condition, exclude) => emit('filter', condition, exclude);

const meaning = useMeaning();

// How long the one-shot arrival classes stay on: a little longer than the
// longest of their animations (alert-in, 2.6 s).
const ARRIVAL_MS = 2700;

const newAlerts = newIdTracker();
const arrivedAlerts = ref(new Set());
const stampedAlerts = ref(new Set());
const unseenAlerts = ref(new Set());
const alertsFlash = ref(false);
let wasBanned = new Map();
let settle = null;
watch(() => props.alerts, (alerts) => {
    const ids = new Set(alerts.map((alert) => alert.id));
    arrivedAlerts.value = newAlerts([...ids]);
    stampedAlerts.value = new Set(alerts.filter((a) => a.banned && wasBanned.get(a.id) === false).map((a) => a.id));
    wasBanned = new Map(alerts.map((a) => [a.id, a.banned]));
    unseenAlerts.value = new Set([...unseenAlerts.value, ...arrivedAlerts.value].filter((id) => ids.has(id)));
    if (arrivedAlerts.value.size) {
        emit('arrived');
        alertsFlash.value = true;
    }
    // Inertia keeps a prop that didn't change, so this won't run again to
    // clear the one-shot classes: drop them once they've played.
    clearTimeout(settle);
    settle = setTimeout(() => {
        arrivedAlerts.value = new Set();
        stampedAlerts.value = new Set();
        alertsFlash.value = false;
    }, ARRIVAL_MS);
}, { immediate: true });
onUnmounted(() => clearTimeout(settle));

function markSeen(id) {
    if (unseenAlerts.value.has(id)) unseenAlerts.value = new Set([...unseenAlerts.value].filter((x) => x !== id));
}

/** Acknowledge or resolve an alert: verb is 'ack' or 'resolve'. */
function act(id, verb) {
    router.post(`/alerts/${id}/${verb}`, {}, { preserveScroll: true });
}
</script>

<template>
    <div class="border bg-panel"
         :class="[alerts.length ? 'border-alarm/40 glow-box' : 'border-grid', alertsFlash ? 'alerts-flash' : '']">
        <div class="border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em]"
                :class="alerts.length ? 'text-alarm' : 'text-ink-dim'">
                Open alerts
            </h2>
        </div>
        <div class="max-h-72 overflow-y-auto">
            <div v-if="!alerts.length" class="px-4 py-6 text-center text-[0.8125rem] text-ink-faint">
                All quiet. No detections in the active windows.
            </div>
            <div
                v-for="alert in alerts"
                :key="alert.id"
                class="border-t border-grid/60 px-4 py-2 first:border-t-0"
                :class="[arrivedAlerts.has(alert.id) ? 'alert-in' : '', unseenAlerts.has(alert.id) ? 'alert-unseen' : '']"
                @mouseenter="markSeen(alert.id)"
                @focusin="markSeen(alert.id)"
            >
                <div class="flex items-center gap-2">
                    <SeverityBadge :severity="alert.severity" />
                    <span class="text-[0.75rem] uppercase tracking-wider text-ink-faint" :title="meaning('rules', alert.rule)">
                        {{ alert.rule.replaceAll('_', ' ') }}
                    </span>
                    <span
                        v-if="unseenAlerts.has(alert.id)"
                        class="flex items-center gap-1 border border-alarm/70 bg-alarm/15 px-1 text-[0.6875rem] uppercase tracking-[0.15em] text-alarm"
                        title="Came in while you were watching; point at it to clear"
                    ><span class="pulse inline-block h-1.5 w-1.5 rounded-full bg-alarm" />new</span>
                    <span
                        v-if="alert.banned"
                        class="ml-auto border border-alarm/60 px-1 text-[0.6875rem] uppercase tracking-[0.15em] text-alarm"
                        :class="stampedAlerts.has(alert.id) ? 'stamp' : ''"
                        title="fail2ban is blocking this address on every port"
                    >banned</span>
                </div>
                <p class="mt-1 text-[0.8125rem] leading-snug">{{ alert.title }}</p>
                <div class="mt-0.5 flex items-center gap-3 text-[0.75rem] text-ink-faint">
                    <span>{{ alert.event_count }} events · {{ alert.last_seen }}</span>
                    <FilterButton
                        v-if="alert.src_ip"
                        class="hover:text-phosphor hover:underline"
                        :condition="`src == ${alert.src_ip}`"
                        @filter="filter"
                    >filter</FilterButton>
                    <Link v-if="alert.src_ip" :href="`/ip/${alert.src_ip}`" class="hover:text-phosphor hover:underline">dossier</Link>
                    <span class="ml-auto flex gap-2">
                        <button class="text-ink-dim hover:text-amber" @click="act(alert.id, 'ack')">ack</button>
                        <button class="text-ink-dim hover:text-phosphor" @click="act(alert.id, 'resolve')">resolve</button>
                    </span>
                </div>
            </div>
        </div>
    </div>
</template>
