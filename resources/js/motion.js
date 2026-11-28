// Shared by the console's effects.

/** True when the viewer asked their system for less motion. */
export function reducedMotion() {
    return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

/**
 * Which ids are new since the last list. Call it with each list as it
 * arrives; it returns the ids it hadn't seen the time before, and none the
 * first time, so whatever is on screen at page load never counts as new.
 */
export function newIdTracker() {
    let seen = null;
    return (ids) => {
        const next = new Set(ids);
        const fresh = seen === null ? new Set() : new Set([...next].filter((id) => !seen.has(id)));
        seen = next;
        return fresh;
    };
}
