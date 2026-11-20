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

// After an upgrade the server answers an old page's requests with a version
// change. Inertia does a full load for a normal visit but silently drops it
// for an async one, and the overview's live poll is async: an open tab would
// keep polling and never update. Do the full load for both. It also replaces
// a page Firefox restored from history with the old version still in it.
router.on('location', (event) => {
    if (!event.detail.versionChange) return;
    const target = event.detail.url;
    if (target.href.split('#')[0] === window.location.href.split('#')[0]) {
        window.location.reload();
    } else {
        window.location.href = target.href;
    }
    return false;
});

// A saved accent reaches every page without a full reload. Partial reloads
// (the overview's live poll) don't carry settings, so they leave it alone.
router.on('navigate', (event) => {
    const settings = event.detail.page.props.settings;
    if (settings) applyAccent(settings.accent, settings.accent_dim);
});
