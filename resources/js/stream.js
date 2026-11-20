// Building display-filter text (App\Services\DisplayFilter) from clicks.

const WORD = /^[A-Za-z0-9_.:/-]+$/;
const KEYWORDS = new Set(['and', 'or', 'not', 'in', 'contains', 'eq', 'ne', 'lt', 'gt', 'le', 'ge']);

/** A value as filter text: bare when it's one plain word, otherwise "quoted". */
export function quote(value) {
    const text = String(value);
    if (WORD.test(text) && !KEYWORDS.has(text.toLowerCase())) {
        return text;
    }
    return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * Add a condition to the current filter with &&, like Wireshark's "Apply as
 * Filter → …and Selected"; exclude adds it as !(condition). A filter with an
 * || is wrapped in parentheses first, so the new condition applies to all
 * of it rather than to its last alternative.
 */
export function combine(current, condition, exclude = false) {
    const test = exclude ? `!(${condition})` : condition;
    const base = (current ?? '').trim();
    if (!base) {
        return test;
    }
    return `${/\|\||\bor\b/i.test(base) ? `(${base})` : base} && ${test}`;
}

const HISTORY_KEY = 'bawls.stream.filters';

/** The last filters this browser applied, newest first (empty when storage is off). */
export function recentFilters() {
    try {
        const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]');
        return Array.isArray(saved) ? saved.filter((f) => typeof f === 'string').slice(0, 10) : [];
    } catch {
        return [];
    }
}

export function rememberFilter(filter) {
    if (!filter) {
        return;
    }
    try {
        const kept = [filter, ...recentFilters().filter((f) => f !== filter)].slice(0, 10);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(kept));
    } catch {
        // Private window or storage off: there's just no history.
    }
}
