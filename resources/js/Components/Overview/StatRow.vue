<script setup>
import StatTile from '../StatTile.vue';

defineProps({ stats: { type: Object, required: true } });
</script>

<template>
    <section class="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-7">
        <StatTile label="Events 24h" :value="stats.events_24h" tone="normal" />
        <StatTile label="Decoy hits 24h" :value="stats.decoy_24h" tone="warn" />
        <StatTile label="Blocked 24h" :value="stats.blocked_24h" tone="warn" />
        <StatTile
            label="Open alerts"
            :value="stats.alerts_open"
            :tone="stats.alerts_open > 0 ? 'alarm' : 'idle'"
        />
        <StatTile
            label="High+"
            :value="stats.alerts_critical"
            :tone="stats.alerts_critical > 0 ? 'alarm' : 'idle'"
        />
        <StatTile
            label="Sensors up"
            :value="`${stats.sensors_online}/${stats.sensors_total}`"
            :tone="stats.sensors_online === stats.sensors_total ? 'normal' : 'warn'"
        />
        <StatTile label="Events stored" :value="stats.events_total" tone="idle" />
    </section>
</template>
