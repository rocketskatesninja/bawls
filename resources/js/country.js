// A country's name from its two-letter code ("DE" -> "Germany"), from the
// browser's own tables. Display only: filters and searches still use the code.
const names = new Intl.DisplayNames(['en'], { type: 'region' });

export function countryName(code) {
    if (!code) return null;
    try {
        return names.of(String(code).toUpperCase()) ?? code;
    } catch {
        return code;   // not a region code: show what we were given
    }
}
