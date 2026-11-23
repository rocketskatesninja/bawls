// Plain-English meanings for signatures, kinds and alert rules, from
// App\Services\Glossary (the shared `glossary` prop).

/** "Tried SQL injection… Bans the address." — or '' for anything unknown. */
export function explain(glossary, group, key) {
    const entry = glossary?.[group]?.[key];
    return entry ? `${entry.text}${entry.bans ? ' Bans the address.' : ''}` : '';
}
