// What the console keeps in the browser: small per-viewer conveniences. Every
// key is named here. Storage can be off (a private window, blocked site data),
// so reads fall back to null and writes are dropped: the page works without it.

export const SOUND = 'bawls.sound'; // 'on' when the new-alert chirp is wanted
export const STREAM_PER_PAGE = 'bawls.stream.per'; // rows per stream page
export const STREAM_FILTERS = 'bawls.stream.filters'; // recent filters, as JSON
export const BOOT_FLAG = 'bawls.boot'; // '1' between a sign-in and the overview's boot sequence

// BOOT_FLAG lasts for the tab's session; the rest are kept.
const store = (key) => (key === BOOT_FLAG ? sessionStorage : localStorage);

export function load(key) {
    try {
        return store(key).getItem(key);
    } catch {
        return null;
    }
}

/** Store a value; null removes the key. */
export function save(key, value) {
    try {
        value === null ? store(key).removeItem(key) : store(key).setItem(key, String(value));
    } catch {
        // Storage off: the choice lasts this page only.
    }
}

/** Read a value and remove it. */
export function take(key) {
    const value = load(key);
    save(key, null);
    return value;
}
