// Console preferences on the client side. The server paints the saved accent
// into the first page (app.blade.php); these keep the page in step after that.

/** The dim shade of an accent: 56% of each channel, as Settings::accentDim(). */
export function dimOf(hex) {
    const channels = [1, 3, 5].map((i) => Math.round(parseInt(hex.slice(i, i + 2), 16) * 0.56));

    return '#' + channels.map((c) => c.toString(16).padStart(2, '0')).join('');
}

/** Recolour the console: every phosphor utility reads these two variables. */
export function applyAccent(accent, dim = dimOf(accent)) {
    const root = document.documentElement.style;
    root.setProperty('--color-phosphor', accent);
    root.setProperty('--color-phosphor-dim', dim);
}

/** "21:40:12" in the given zone, matching the server's H:i:s. */
export function clock(date, timeZone) {
    return date.toLocaleTimeString('en-GB', { timeZone, hourCycle: 'h23' });
}

/** WCAG contrast ratio against the console's background, as Settings::contrast(). */
export function contrast(hex, background = '#070b09') {
    const luminance = (h) => {
        const [r, g, b] = [1, 3, 5].map((i) => {
            const c = parseInt(h.slice(i, i + 2), 16) / 255;
            return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const [a, b] = [luminance(hex), luminance(background)];

    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}
