<script setup>
import { onMounted, onUnmounted, ref } from 'vue';

// The overview's keyboard shortcuts: "/" asks the page to focus the filter,
// "?" shows this list. Ignored while typing in a field or with a modifier
// held (browser and OS shortcuts).
const emit = defineEmits(['focus-filter']);

const showKeys = ref(false);
const shortcuts = [
    ['/', 'Jump to the filter'],
    ['Enter', 'Apply the filter'],
    ['Esc', 'Undo filter edits · close the details · close this list'],
    ['↑ ↓', 'Move through the stream (click it first)'],
    ['Alt + click', 'Exclude instead of filter'],
    ['?', 'Show or hide this list'],
];

function onKey(event) {
    if (event.key === 'Escape' && showKeys.value) {
        showKeys.value = false;
        return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    const target = event.target;
    if (target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))) return;
    if (event.key === '/') {
        event.preventDefault();
        emit('focus-filter');
    } else if (event.key === '?') {
        event.preventDefault();
        showKeys.value = !showKeys.value;
    }
}

onMounted(() => window.addEventListener('keydown', onKey));
onUnmounted(() => window.removeEventListener('keydown', onKey));

defineExpose({ toggle: () => (showKeys.value = !showKeys.value) });
</script>

<template>
    <div v-if="showKeys" class="fixed inset-0 z-40 flex items-center justify-center bg-void/70" @click.self="showKeys = false">
        <div role="dialog" aria-label="Keyboard shortcuts" class="w-[22rem] border border-edge bg-panel p-4 text-[0.8125rem] glow-box">
            <div class="mb-3 flex items-center justify-between">
                <h2 class="text-[0.8125rem] uppercase tracking-[0.2em] text-ink-dim">Keyboard</h2>
                <button type="button" aria-label="Close" class="text-ink-faint hover:text-phosphor" @click="showKeys = false">✕</button>
            </div>
            <dl class="grid grid-cols-[auto_1fr] items-baseline gap-x-4 gap-y-2">
                <template v-for="[keys, what] in shortcuts" :key="keys">
                    <dt><kbd class="border border-edge bg-panel-lit px-1.5 py-0.5 text-[0.75rem] text-phosphor">{{ keys }}</kbd></dt>
                    <dd class="text-ink-dim">{{ what }}</dd>
                </template>
            </dl>
        </div>
    </div>
</template>
