<script setup>
defineProps({ size: { type: Number, default: 26 } });
</script>

<template>
    <!-- The console's mark: a target reticle. One copy, used by every page header. -->
    <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" class="text-phosphor glow">
        <circle cx="12" cy="12" r="9.5" stroke="currentColor" stroke-width="1.2" opacity="0.5" />
        <circle cx="12" cy="12" r="5" stroke="currentColor" stroke-width="1.2" opacity="0.8" />
        <circle cx="12" cy="12" r="1.6" fill="currentColor" />
        <path d="M12 2.5V6M12 18v3.5M2.5 12H6M18 12h3.5" stroke="currentColor" stroke-width="1.2" />
    </svg>
</template>
