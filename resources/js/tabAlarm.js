import { computed, onMounted, onUnmounted, ref, watch } from 'vue';

// The browser tab as an alarm, so an alert is noticed from another tab: its
// title names the open-alert count, its icon gets a red dot while any alert
// is open, and a ● leads the title when one came in while the tab was in the
// background. The icon is the page's own inline SVG (app.blade.php) with the
// dot added; leaving the page puts it back.

const ALARM_DOT = "%3Ccircle cx='25' cy='7' r='6' fill='%23ff2d55' stroke='%23070b09' stroke-width='2'/%3E";

/**
 * @param {() => number} openAlerts how many alerts are open
 * @param {string} name the page's own title
 * @returns {{ title: import('vue').ComputedRef<string>, noteArrival: () => void }}
 */
export function useTabAlarm(openAlerts, name) {
    const missedWhileAway = ref(false);
    const title = computed(() => `${missedWhileAway.value ? '● ' : ''}${openAlerts() > 0 ? `(${openAlerts()}) ` : ''}${name}`);

    let icon = null;
    let plainIcon = null;
    function showAlarmIcon(open) {
        if (icon && plainIcon) icon.setAttribute('href', open > 0 ? plainIcon.replace('%3C/svg%3E', `${ALARM_DOT}%3C/svg%3E`) : plainIcon);
    }
    const backInView = () => !document.hidden && (missedWhileAway.value = false);

    onMounted(() => {
        icon = document.querySelector('link[rel=icon]');
        plainIcon = icon?.getAttribute('href') ?? null;
        showAlarmIcon(openAlerts());
        document.addEventListener('visibilitychange', backInView);
    });
    watch(openAlerts, showAlarmIcon);
    onUnmounted(() => {
        showAlarmIcon(0);
        document.removeEventListener('visibilitychange', backInView);
    });

    return {
        title,
        /** Call when a new alert opens: marks the title if nobody is looking. */
        noteArrival() {
            if (document.hidden) missedWhileAway.value = true;
        },
    };
}
