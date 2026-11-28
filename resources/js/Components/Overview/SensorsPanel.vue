<script setup>
// Each sensor: online (and how many events it has sent) or when it was last heard from.
defineProps({ sensors: { type: Array, required: true } }); // [{ name, online, last_seen, events }]
</script>

<template>
    <div class="border border-grid bg-panel">
        <div class="border-b border-grid px-4 py-2">
            <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Sensors</h2>
        </div>
        <div v-for="sensor in sensors" :key="sensor.name"
             class="flex items-center justify-between border-t border-grid/60 px-4 py-1.5 text-[0.8125rem] first:border-t-0">
            <div class="flex items-center gap-2">
                <span class="h-1.5 w-1.5 rounded-full"
                      :class="sensor.online ? 'bg-phosphor' : 'bg-ink-faint'" />
                <span>{{ sensor.name }}</span>
            </div>
            <span class="tabular-nums text-ink-faint">
                {{ sensor.online ? sensor.events.toLocaleString() : (sensor.last_seen ?? 'never') }}
            </span>
        </div>
        <div v-if="!sensors.length" class="px-4 py-4 text-center text-[0.8125rem] text-ink-faint">
            No sensors registered.
        </div>
    </div>
</template>
