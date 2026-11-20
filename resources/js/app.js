import { createApp, h } from 'vue';
import { createInertiaApp, router } from '@inertiajs/vue3';
import { applyAccent } from './settings';

createInertiaApp({
    title: (title) => (title ? `${title} — Bawls` : 'Bawls'),
    // Pages load on demand, so MapLibre (~1 MB) ships only with the /ip page,
    // not with the sign-in page or the dashboard.
    resolve: (name) => import.meta.glob('./Pages/**/*.vue')[`./Pages/${name}.vue`](),
    setup({ el, App, props, plugin }) {
        createApp({ render: () => h(App, props) })
            .use(plugin)
            .mount(el);
    },
});

// A saved accent reaches every page without a full reload. Partial reloads
// (the overview's live poll) don't carry settings, so they leave it alone.
router.on('navigate', (event) => {
    const settings = event.detail.page.props.settings;
    if (settings) applyAccent(settings.accent, settings.accent_dim);
});
