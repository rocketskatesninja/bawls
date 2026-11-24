// How each kind of event (App\Models\Event::KINDS) looks in the console:
// Wireshark-style colouring rules. A row's text also names what happened (the
// signature, "blocked"), so the colour is never the only signal.
//
// The chart (TrafficChart.vue) and the attack map (AttackMap.vue) draw with
// SVG fills and keep their own hex values for the same kinds.

export const KIND_LABEL = { exploit: 'exploit', login: 'login', scan: 'scan', page: 'page view', firewall: 'firewall', other: 'event' };

/** The text colour of a row or value of this kind. */
export const KIND_TONE = {
    exploit: 'text-alarm',
    login: 'text-signal',
    scan: 'text-amber',
    page: 'text-ink-dim',
    firewall: 'text-ink-faint',
    other: 'text-ink',
};

/** The left edge of a stream row: only the kinds worth a second look get one. */
export const KIND_BAR = {
    exploit: 'border-l-alarm',
    login: 'border-l-signal',
    scan: 'border-l-amber',
    page: 'border-l-transparent',
    firewall: 'border-l-transparent',
    other: 'border-l-transparent',
};

/** The stream's legend: [label, swatch class, kind]. */
export const LEGEND = [
    ['exploit', 'bg-alarm', 'exploit'],
    ['login', 'bg-signal', 'login'],
    ['scan', 'bg-amber', 'scan'],
    ['page view', 'bg-ink-dim', 'page'],
    ['firewall', 'bg-ink-faint', 'firewall'],
];
