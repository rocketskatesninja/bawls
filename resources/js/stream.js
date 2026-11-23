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
    return `${topLevelTerms(base) === null ? `(${base})` : base} && ${test}`;
}

/**
 * A filter's top-level && terms: split outside parentheses, sets and
 * "quotes". Null when it has a top-level || (or "or"), whose terms can't be
 * taken apart without changing what it means.
 */
function topLevelTerms(filter) {
    const terms = [];
    let depth = 0;
    let quoted = false;
    let start = 0;
    for (let i = 0; i < filter.length; i++) {
        const c = filter[i];
        if (quoted) {
            if (c === '\\') i++;
            else if (c === '"') quoted = false;
            continue;
        }
        if (c === '"') quoted = true;
        else if (c === '(' || c === '{') depth++;
        else if (c === ')' || c === '}') depth--;
        else if (depth === 0) {
            const atWord = i === 0 || /[\s)]/.test(filter[i - 1]);
            const word = atWord ? /^(and|or)(?=[\s(!])/i.exec(filter.slice(i)) : null;
            if (filter.startsWith('||', i) || word?.[1].toLowerCase() === 'or') return null;
            const join = filter.startsWith('&&', i) ? 2 : word ? 3 : 0;
            if (join) {
                terms.push(filter.slice(start, i).trim());
                start = i + join;
                i += join - 1;
            }
        }
    }
    terms.push(filter.slice(start).trim());
    return terms;
}

const HOUR_START = /^time >= "([^"]*)"$/;
const HOUR_END = /^time < "[^"]*"$/;

/** Where a chart click's hour sits among the terms (its `time >=` term), or -1. */
function hourAt(terms) {
    return terms.findIndex((term, i) => HOUR_START.test(term) && HOUR_END.test(terms[i + 1] ?? ''));
}

/** The `from` of the hour the filter is narrowed to by a chart click, if any. */
export function pickedHour(filter) {
    const terms = topLevelTerms((filter ?? '').trim());
    const at = terms ? hourAt(terms) : -1;
    return at === -1 ? null : terms[at].match(HOUR_START)[1];
}

/**
 * Narrow the filter to one hour of the chart. It replaces an hour picked
 * earlier (two different hours together would match nothing), and picking
 * the same hour again clears it.
 */
export function pickHour(filter, from, to) {
    const text = (filter ?? '').trim();
    const hour = `time >= ${quote(from)} && time < ${quote(to)}`;
    const terms = text ? topLevelTerms(text) : null;
    const at = terms ? hourAt(terms) : -1;
    if (at === -1) {
        return combine(text, hour);
    }
    const rest = terms.filter((_, i) => i !== at && i !== at + 1).join(' && ');
    return terms[at].match(HOUR_START)[1] === from ? rest : combine(rest, hour);
}

/** The filter's top-level && terms; one term when it has a top-level ||. */
export function filterTerms(filter) {
    const text = (filter ?? '').trim();
    return text ? topLevelTerms(text) ?? [text] : [];
}

/**
 * The filter as chips you can remove one at a time: one per top-level &&
 * term, with a chart hour's two time terms as a single "hour" chip.
 * `at` is the chip's term positions, for removeChip.
 */
export function filterChips(filter) {
    const terms = filterTerms(filter);
    const chips = [];
    for (let i = 0; i < terms.length; i++) {
        if (HOUR_START.test(terms[i]) && HOUR_END.test(terms[i + 1] ?? '')) {
            chips.push({ label: `hour from ${terms[i].match(HOUR_START)[1]}`, at: [i, i + 1] });
            i++;
        } else {
            chips.push({ label: terms[i], at: [i] });
        }
    }
    return chips;
}

export function removeChip(filter, chip) {
    return filterTerms(filter).filter((_, i) => !chip.at.includes(i)).join(' && ');
}

/** Add a top-level term, or take it out when it's already there. */
export function toggleTerm(filter, term) {
    const terms = filterTerms(filter);
    return terms.includes(term) ? terms.filter((t) => t !== term).join(' && ') : combine(filter, term);
}

/** The filter's lone `time >= "…"` chip (a start with no end, like Last hour's), if any. */
export function sinceChip(filter) {
    return filterChips(filter).find((chip) => chip.at.length === 1 && HOUR_START.test(chip.label)) ?? null;
}

/** A moment as the filter's `time` reads it: "2026-11-23 14:05" in the display zone. */
export function filterMinute(date, timeZone) {
    const parts = Object.fromEntries(
        new Intl.DateTimeFormat('en-CA', {
            timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
        }).formatToParts(date).map((part) => [part.type, part.value])
    );
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}`;
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
