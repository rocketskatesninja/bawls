<?php

namespace App\Services;

use App\Models\Event;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Builder as QueryBuilder;

/**
 * The event stream's display filter: a small Wireshark-like language, e.g.
 *
 *   src == 203.0.113.9 && path contains "wp-" && !(sig == benign)
 *
 * Grammar (&& binds tighter than ||, as in Wireshark):
 *
 *   or   := and (('||' | or) and)*
 *   and  := not (('&&' | and) not)*
 *   not  := ('!' | not) not | '(' or ')' | test
 *   test := FLAG | FIELD op value | FIELD in '{' value+ '}'
 *
 * Field names map to fixed columns and JSON paths, and every value is a bound
 * parameter, so nothing typed reaches SQL as text. A comparison only matches
 * events that have the field: `path != "/"` skips firewall events, while
 * `!(path == "/")` includes them.
 */
class DisplayFilter
{
    public const MAX_LENGTH = 500;

    public const MAX_TESTS = 40;

    public const MAX_DEPTH = 10;

    private const MAX_SET = 50;

    private const MAX_VALUE = 200;

    /**
     * type: how values are read and compared. sql: fixed SQL expressions (one
     * per column; "either" fields such as ip list two). intel: a column of
     * ip_intel, looked up by the event's source address.
     */
    private const FIELDS = [
        'ip' => ['type' => 'ip', 'sql' => ['src_ip', 'dst_ip']],
        'src' => ['type' => 'ip', 'sql' => ['src_ip']],
        'dst' => ['type' => 'ip', 'sql' => ['dst_ip']],
        'port' => ['type' => 'int', 'sql' => ['src_port', 'dst_port']],
        'src.port' => ['type' => 'int', 'sql' => ['src_port']],
        'dst.port' => ['type' => 'int', 'sql' => ['dst_port']],
        'proto' => ['type' => 'text', 'sql' => ['proto']],
        'action' => ['type' => 'text', 'sql' => ['action']],
        'dir' => ['type' => 'text', 'sql' => ['direction']],
        'process' => ['type' => 'text', 'sql' => ['process']],
        'method' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.method')"]],
        'path' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.path')"]],
        'query' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.query')"]],
        'ua' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.user_agent')"]],
        'http.host' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.host')"]],
        'referer' => ['type' => 'text', 'sql' => ["json_extract(raw, '$.referer')"]],
        'status' => ['type' => 'int', 'sql' => ["json_extract(raw, '$.status')"]],
        'sig' => ['type' => 'sig', 'sql' => ["json_extract(raw, '$.signature')"]],
        // Which website a request came in on: "decoy", or a real site's name.
        'site' => ['type' => 'text', 'sql' => ["CASE WHEN source = 'honeypot_http' THEN 'decoy' ELSE json_extract(raw, '$.site') END"]],
        'country' => ['type' => 'text', 'intel' => 'country'],
        'asn' => ['type' => 'int', 'intel' => 'asn'],
        'org' => ['type' => 'text', 'intel' => 'as_org'],
        'time' => ['type' => 'time', 'sql' => ['occurred_at']],
        'no' => ['type' => 'int', 'sql' => ['id']],
        'http' => ['type' => 'flag'],
        'decoy' => ['type' => 'flag'],
        'ufw' => ['type' => 'flag'],
        'login' => ['type' => 'flag'],
        'banned' => ['type' => 'flag'],
    ];

    /** Wireshark's names for the same fields. */
    private const ALIASES = [
        'ip.addr' => 'ip', 'ip.src' => 'src', 'ip.dst' => 'dst',
        'tcp.port' => 'port', 'udp.port' => 'port',
        'tcp.srcport' => 'src.port', 'udp.srcport' => 'src.port',
        'tcp.dstport' => 'dst.port', 'udp.dstport' => 'dst.port',
        'direction' => 'dir', 'signature' => 'sig',
        'http.request.method' => 'method', 'http.request.uri' => 'path',
        'http.user_agent' => 'ua', 'http.referer' => 'referer', 'http.response.code' => 'status',
        'frame.time' => 'time', 'frame.number' => 'no',
    ];

    private const OPS = [
        'ip' => ['==', '!=', 'in'],
        'int' => ['==', '!=', '<', '>', '<=', '>=', 'in'],
        'text' => ['==', '!=', 'contains', 'in'],
        'sig' => ['==', '!=', 'in'],
        'time' => ['==', '!=', '<', '>', '<=', '>='],
    ];

    /** Wireshark's word operators. */
    private const WORD_OPS = ['eq' => '==', 'ne' => '!=', 'lt' => '<', 'gt' => '>', 'le' => '<=', 'ge' => '>=', 'contains' => 'contains', 'in' => 'in'];

    private const SYMBOLS = ['&&', '||', '==', '!=', '<=', '>=', '<', '>', '!', '(', ')', '{', '}', ','];

    /** @var list<array{kind: string, text: string, at: int}> */
    private array $tokens = [];

    private int $next = 0;

    private int $tests = 0;

    /** @var array<string, mixed> */
    private array $tree = [];

    private function __construct() {}

    /**
     * Parse a filter. Null when it's empty, which means "everything".
     *
     * @throws DisplayFilterError
     */
    public static function parse(string $text): ?self
    {
        if (trim($text) === '') {
            return null;
        }
        if (mb_strlen($text) > self::MAX_LENGTH) {
            throw new DisplayFilterError('The filter is too long ('.self::MAX_LENGTH.' characters at most).', self::MAX_LENGTH);
        }

        $filter = new self;
        $filter->tokens = self::tokenize($text);
        $filter->tree = $filter->parseOr(0);
        if ($filter->peek() !== null) {
            $token = $filter->peek();
            throw new DisplayFilterError("Unexpected \"{$token['text']}\": join conditions with && or ||.", $token['at']);
        }
        $filter->tokens = [];

        return $filter;
    }

    /** A value as filter text: bare when it's one plain word, otherwise "quoted". */
    public static function quote(string|int $value): string
    {
        $text = (string) $value;
        $keyword = isset(self::WORD_OPS[strtolower($text)]) || in_array(strtolower($text), ['and', 'or', 'not'], true);

        return preg_match('/^[A-Za-z0-9_.:\/\-]+$/', $text) && ! $keyword
            ? $text
            : '"'.addcslashes($text, '"\\').'"';
    }

    /** Narrow an events query to what the filter matches; times are read in $timezone. */
    public function apply(Builder $query, string $timezone): Builder
    {
        return $query->where(fn (Builder $q) => $this->node($q, $this->tree, $timezone));
    }

    // ------------------------------------------------------------------ lexing

    /**
     * @return list<array{kind: string, text: string, at: int}>
     */
    private static function tokenize(string $text): array
    {
        $tokens = [];
        $length = strlen($text);
        $i = 0;
        while ($i < $length) {
            if (ctype_space($text[$i])) {
                $i++;

                continue;
            }
            if ($text[$i] === '"') {
                $start = $i++;
                $value = '';
                while ($i < $length && $text[$i] !== '"') {
                    if ($text[$i] === '\\' && $i + 1 < $length) {
                        $i++;
                    }
                    $value .= $text[$i++];
                }
                if ($i >= $length) {
                    throw new DisplayFilterError('A quote is never closed.', $start);
                }
                $i++;
                $tokens[] = ['kind' => 'string', 'text' => $value, 'at' => $start];

                continue;
            }
            foreach (self::SYMBOLS as $symbol) {
                if (substr_compare($text, $symbol, $i, strlen($symbol)) === 0) {
                    $tokens[] = ['kind' => 'symbol', 'text' => $symbol, 'at' => $i];
                    $i += strlen($symbol);

                    continue 2;
                }
            }
            if (preg_match('/\G[A-Za-z0-9_.:\/\-]+/', $text, $match, 0, $i)) {
                $tokens[] = ['kind' => 'word', 'text' => $match[0], 'at' => $i];
                $i += strlen($match[0]);

                continue;
            }
            throw new DisplayFilterError(match ($text[$i]) {
                '=' => 'Compare with ==, not =.',
                '&' => 'Join conditions with &&, not &.',
                '|' => 'Join alternatives with ||, not |.',
                default => "Unexpected \"{$text[$i]}\": put text with spaces or symbols in \"quotes\".",
            }, $i);
        }

        return $tokens;
    }

    // ----------------------------------------------------------------- parsing

    /** @return array{kind: string, text: string, at: int}|null */
    private function peek(): ?array
    {
        return $this->tokens[$this->next] ?? null;
    }

    private function nextIs(string $symbol, ?string $word = null): bool
    {
        $token = $this->peek();

        return $token !== null && (
            ($token['kind'] === 'symbol' && $token['text'] === $symbol)
            || ($word !== null && $token['kind'] === 'word' && strtolower($token['text']) === $word)
        );
    }

    private function end(): int
    {
        $last = end($this->tokens);

        return $last === false ? 0 : $last['at'] + strlen($last['text']);
    }

    /** @return array<string, mixed> */
    private function parseOr(int $depth): array
    {
        $children = [$this->parseAnd($depth)];
        while ($this->nextIs('||', 'or')) {
            $this->next++;
            $children[] = $this->parseAnd($depth);
        }

        return count($children) === 1 ? $children[0] : ['type' => 'or', 'children' => $children];
    }

    /** @return array<string, mixed> */
    private function parseAnd(int $depth): array
    {
        $children = [$this->parseNot($depth)];
        while ($this->nextIs('&&', 'and')) {
            $this->next++;
            $children[] = $this->parseNot($depth);
        }

        return count($children) === 1 ? $children[0] : ['type' => 'and', 'children' => $children];
    }

    /** @return array<string, mixed> */
    private function parseNot(int $depth): array
    {
        if ($depth > self::MAX_DEPTH) {
            throw new DisplayFilterError('The filter is nested too deeply.', $this->peek()['at'] ?? $this->end());
        }
        if ($this->nextIs('!', 'not')) {
            $this->next++;

            return ['type' => 'not', 'child' => $this->parseNot($depth + 1)];
        }
        if ($this->nextIs('(')) {
            $open = $this->peek()['at'];
            $this->next++;
            $node = $this->parseOr($depth + 1);
            if (! $this->nextIs(')')) {
                throw new DisplayFilterError('A "(" is never closed.', $open);
            }
            $this->next++;

            return $node;
        }

        return $this->parseTest();
    }

    /** @return array<string, mixed> */
    private function parseTest(): array
    {
        $token = $this->peek();
        if ($token === null) {
            throw new DisplayFilterError('The filter ends too soon: a condition is missing.', $this->end());
        }
        if ($token['kind'] !== 'word') {
            throw new DisplayFilterError("Expected a field name, not \"{$token['text']}\".", $token['at']);
        }
        $name = strtolower($token['text']);
        $field = self::ALIASES[$name] ?? $name;
        if (! isset(self::FIELDS[$field])) {
            throw new DisplayFilterError("Unknown field \"{$token['text']}\".", $token['at']);
        }
        if (++$this->tests > self::MAX_TESTS) {
            throw new DisplayFilterError('Too many conditions ('.self::MAX_TESTS.' at most).', $token['at']);
        }
        $this->next++;

        $type = self::FIELDS[$field]['type'];
        $op = $this->operator();
        if ($type === 'flag') {
            if ($op !== null) {
                throw new DisplayFilterError("\"{$field}\" is a flag: use it on its own, like \"{$field} && sig == sqli\".", $op['at']);
            }

            return ['type' => 'test', 'field' => $field, 'op' => null, 'values' => []];
        }
        if ($op === null) {
            throw new DisplayFilterError("\"{$field}\" needs a comparison, like ".self::example($field).'.', $token['at']);
        }
        if (! in_array($op['op'], self::OPS[$type], true)) {
            throw new DisplayFilterError("\"{$field}\" can't use {$op['op']}; it takes ".implode(' ', self::OPS[$type]).'.', $op['at']);
        }

        $values = $op['op'] === 'in' ? $this->valueSet() : [$this->value()];

        return [
            'type' => 'test',
            'field' => $field,
            'op' => $op['op'],
            'values' => array_map(fn (array $value): mixed => self::normalize($field, $type, $value), $values),
        ];
    }

    /** @return array{op: string, at: int}|null */
    private function operator(): ?array
    {
        $token = $this->peek();
        if ($token === null) {
            return null;
        }
        $op = match ($token['kind']) {
            'symbol' => in_array($token['text'], ['==', '!=', '<', '>', '<=', '>='], true) ? $token['text'] : null,
            'word' => self::WORD_OPS[strtolower($token['text'])] ?? null,
            default => null,
        };
        if ($op === null) {
            return null;
        }
        $this->next++;

        return ['op' => $op, 'at' => $token['at']];
    }

    /** @return array{kind: string, text: string, at: int} */
    private function value(): array
    {
        $token = $this->peek();
        if ($token === null || $token['kind'] === 'symbol') {
            throw new DisplayFilterError('A value is missing here.', $token['at'] ?? $this->end());
        }
        $this->next++;

        return $token;
    }

    /** @return list<array{kind: string, text: string, at: int}> */
    private function valueSet(): array
    {
        if (! $this->nextIs('{')) {
            throw new DisplayFilterError('"in" takes a set, like {22 80 443}.', $this->peek()['at'] ?? $this->end());
        }
        $open = $this->peek()['at'];
        $this->next++;
        $values = [];
        while (! $this->nextIs('}')) {
            if ($this->peek() === null) {
                throw new DisplayFilterError('A "{" is never closed.', $open);
            }
            if ($this->nextIs(',')) {
                $this->next++;

                continue;
            }
            $values[] = $this->value();
        }
        $this->next++;
        if ($values === [] || count($values) > self::MAX_SET) {
            throw new DisplayFilterError('A set holds 1 to '.self::MAX_SET.' values.', $open);
        }

        return $values;
    }

    /**
     * Check a value against its field and put it in the form the query uses.
     *
     * @param  array{kind: string, text: string, at: int}  $token
     */
    private static function normalize(string $field, string $type, array $token): mixed
    {
        $value = $token['text'];
        if (mb_strlen($value) > self::MAX_VALUE) {
            throw new DisplayFilterError('That value is too long ('.self::MAX_VALUE.' characters at most).', $token['at']);
        }

        return match ($type) {
            'ip' => self::ipValue($value, $token['at']),
            'int' => ctype_digit($value) && strlen($value) <= 10
                ? (int) $value
                : throw new DisplayFilterError("\"{$field}\" takes a whole number, not \"{$value}\".", $token['at']),
            'time' => self::timeValue($value, $token['at']),
            default => mb_strtolower($value),
        };
    }

    /**
     * An address, or an IPv4 range on a whole-octet boundary (LIKE can match
     * a text prefix, not arbitrary bits).
     *
     * @return array{exact?: string, prefix?: string}
     */
    private static function ipValue(string $value, int $at): array
    {
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return ['exact' => strtolower($value)];
        }
        if (preg_match('#^(\d{1,3}(?:\.\d{1,3}){3})/(8|16|24|32)$#', $value, $match)
            && filter_var($match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $octets = (int) $match[2] / 8;
            $parts = array_slice(explode('.', $match[1]), 0, $octets);

            return $octets === 4 ? ['exact' => $match[1]] : ['prefix' => implode('.', $parts).'.'];
        }

        throw new DisplayFilterError("\"{$value}\" isn't an address or a /8, /16, /24 or /32 IPv4 range.", $at);
    }

    /**
     * A day, minute or second in the display zone, kept as text until apply()
     * knows the zone.
     *
     * @return array{text: string, unit: string}
     */
    private static function timeValue(string $value, int $at): array
    {
        $formats = ['second' => '!Y-m-d H:i:s', 'minute' => '!Y-m-d H:i', 'day' => '!Y-m-d'];
        $text = str_replace('T', ' ', $value);
        foreach ($formats as $unit => $format) {
            $time = DateTimeImmutable::createFromFormat($format, $text);
            if ($time !== false && $time->format(substr($format, 1)) === $text) {
                return ['text' => $text, 'unit' => $unit];
            }
        }

        throw new DisplayFilterError("\"{$value}\" isn't a time: write it like \"2026-11-20 14:00\".", $at);
    }

    private static function example(string $field): string
    {
        return match (self::FIELDS[$field]['type']) {
            'ip' => "{$field} == 203.0.113.9",
            'int' => "{$field} == 22",
            'time' => "{$field} >= \"2026-11-20 14:00\"",
            'sig' => "{$field} == sqli",
            default => "{$field} contains \"wp-\"",
        };
    }

    // ---------------------------------------------------------------- querying

    /** @param array<string, mixed> $node */
    private function node(Builder $q, array $node, string $timezone): void
    {
        match ($node['type']) {
            'or' => $q->where(function (Builder $group) use ($node, $timezone): void {
                foreach ($node['children'] as $child) {
                    $group->orWhere(fn (Builder $one) => $this->node($one, $child, $timezone));
                }
            }),
            'and' => array_map(fn (array $child) => $this->node($q, $child, $timezone), $node['children']),
            'not' => $q->whereNot(fn (Builder $inner) => $this->node($inner, $node['child'], $timezone)),
            'test' => $q->where(fn (Builder $inner) => $this->test($inner, $node, $timezone)),
        };
    }

    /** @param array<string, mixed> $test */
    private function test(Builder $q, array $test, string $timezone): void
    {
        $field = self::FIELDS[$test['field']];
        if ($field['type'] === 'flag') {
            $this->flag($q, $test['field']);

            return;
        }
        if ($test['op'] === '!=') {
            // "Has the field, and it isn't": the presence check keeps events
            // without the field out, as in Wireshark.
            $this->present($q, $field);
            $q->whereNot(fn (Builder $inner) => $this->matches($inner, $field, '==', $test['values'], $timezone));

            return;
        }
        $this->matches($q, $field, $test['op'] === 'in' ? '==' : $test['op'], $test['values'], $timezone);
    }

    /**
     * True when any value matches in any of the field's columns.
     *
     * @param  array<string, mixed>  $field
     * @param  list<mixed>  $values
     */
    private function matches(Builder $q, array $field, string $op, array $values, string $timezone): void
    {
        if (isset($field['intel'])) {
            $q->whereIn('src_ip', fn ($intel) => $intel->select('ip')->from('ip_intel')
                ->where(function ($any) use ($field, $op, $values, $timezone): void {
                    foreach ($values as $value) {
                        $any->orWhere(fn ($one) => $this->compare($one, $field['type'], $field['intel'], $op, $value, $timezone));
                    }
                }));

            return;
        }
        $q->where(function (Builder $any) use ($field, $op, $values, $timezone): void {
            foreach ($values as $value) {
                foreach ($field['sql'] as $sql) {
                    $any->orWhere(fn (Builder $one) => $this->compare($one, $field['type'], $sql, $op, $value, $timezone));
                }
            }
        });
    }

    /**
     * One comparison. $sql is always one of the fixed expressions in FIELDS,
     * never filter text; $value is always bound.
     */
    private function compare(Builder|QueryBuilder $q, string $type, string $sql, string $op, mixed $value, string $timezone): void
    {
        if ($type === 'sig' && $value === 'benign') {
            // The decoy leaves ordinary page views unlabelled.
            $q->whereIn('source', Event::HTTP_SOURCES)->whereRaw("coalesce(lower({$sql}), 'benign') = 'benign'");

            return;
        }
        $q->whereRaw("{$sql} IS NOT NULL");

        if ($type === 'ip') {
            isset($value['prefix'])
                ? $q->whereRaw("{$sql} LIKE ?", [$value['prefix'].'%'])
                : $q->whereRaw("{$sql} = ?", [$value['exact']]);

            return;
        }
        if ($type === 'int') {
            $q->whereRaw("{$sql} ".($op === '==' ? '=' : $op).' ?', [$value]);

            return;
        }
        if ($type === 'time') {
            [$start, $end] = $this->timeRange($value, $timezone);
            match ($op) {
                '==' => $q->whereRaw("{$sql} >= ? AND {$sql} < ?", [$start, $end]),
                '<' => $q->whereRaw("{$sql} < ?", [$start]),
                '<=' => $q->whereRaw("{$sql} < ?", [$end]),
                '>' => $q->whereRaw("{$sql} >= ?", [$end]),
                '>=' => $q->whereRaw("{$sql} >= ?", [$start]),
            };

            return;
        }
        if ($op === 'contains') {
            $q->whereRaw("{$sql} LIKE ? ESCAPE '\\'", ['%'.addcslashes($value, '%_\\').'%']);

            return;
        }
        $q->whereRaw("lower({$sql}) = ?", [$value]);
    }

    /**
     * Where a field exists at all, for "!=".
     *
     * @param  array<string, mixed>  $field
     */
    private function present(Builder $q, array $field): void
    {
        if (isset($field['intel'])) {
            $q->whereIn('src_ip', fn ($intel) => $intel->select('ip')->from('ip_intel')->whereNotNull($field['intel']));

            return;
        }
        if ($field['type'] === 'sig') {
            $q->whereIn('source', Event::HTTP_SOURCES);

            return;
        }
        $q->where(function (Builder $any) use ($field): void {
            foreach ($field['sql'] as $sql) {
                $any->orWhereRaw("{$sql} IS NOT NULL");
            }
        });
    }

    private function flag(Builder $q, string $flag): void
    {
        match ($flag) {
            'http' => $q->whereIn('source', Event::HTTP_SOURCES),
            'decoy' => $q->where('source', 'honeypot_http'),
            'ufw' => $q->where('source', 'ufw_block'),
            'login' => $q->where('source', 'honeypot_http')->where(fn (Builder $login) => $login
                ->whereRaw("coalesce(json_extract(raw, '$.login_attempt'), 0) = 1")
                ->orWhereRaw("json_extract(raw, '$.signature') = 'login'")),
            'banned' => $q->whereIn('src_ip', array_column(Bans::current()['bans'], 'ip') ?: ['']),
        };
    }

    /**
     * The UTC bounds of a day, minute or second written in the display zone.
     *
     * @param  array{text: string, unit: string}  $value
     * @return array{0: string, 1: string}
     */
    private function timeRange(array $value, string $timezone): array
    {
        $format = ['second' => '!Y-m-d H:i:s', 'minute' => '!Y-m-d H:i', 'day' => '!Y-m-d'][$value['unit']];
        $start = DateTimeImmutable::createFromFormat($format, $value['text'], new DateTimeZone($timezone));
        $end = $start->modify("+1 {$value['unit']}");
        $utc = new DateTimeZone('UTC');

        return [$start->setTimezone($utc)->format('Y-m-d H:i:s'), $end->setTimezone($utc)->format('Y-m-d H:i:s')];
    }
}
