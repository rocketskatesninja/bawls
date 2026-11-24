// Plain-English meanings for signatures, kinds and alert rules, from
// App\Services\Glossary (the shared `glossary` prop).

import { usePage } from '@inertiajs/vue3';

/** For a component: meaning(group, key) reads the glossary from the page's shared props. */
export function useMeaning() {
    const page = usePage();
    return (group, key) => explain(page.props.glossary, group, key);
}

/** "Tried SQL injection… Bans the address." — or '' for anything unknown. */
export function explain(glossary, group, key) {
    const entry = glossary?.[group]?.[key];
    return entry ? `${entry.text}${entry.bans ? ' Bans the address.' : ''}` : '';
}
