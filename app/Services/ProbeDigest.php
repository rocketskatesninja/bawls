<?php

namespace App\Services;

use App\Models\Event;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * The weekly digest of what the signatures missed: decoy requests that
 * matched no attack pattern but look like probing, not browsing. That is an
 * unknown path (the decoy answered something other than 200, or 503 for a
 * flood), a query string, or a method other than GET or HEAD; plain page
 * views are left out. Grouped by method and path and ranked by how many
 * addresses tried it, so a new exploit probe stands out for adding to the
 * sensor's patterns (sensors/signatures.py).
 */
class ProbeDigest
{
    /** How far back the digest looks, and how many rows it shows. */
    private const DAYS = 7;

    private const ROWS = 15;

    private const METHOD_SQL = "COALESCE(json_extract(raw, '$.method'), 'GET')";

    private const PATH_SQL = "json_extract(raw, '$.path')";

    public function __construct(private ProbeCatalog $probes) {}

    /**
     * @return array{days: int, hits: int, sources: int, rows: list<array{method: string, path: string, hits: int, sources: int, last_seen: string, query: ?string, queries: int, explain: array<string, mixed>|null, filter: string}>}
     */
    public function all(): array
    {
        $totals = $this->missed()->selectRaw('COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources')->first();

        $groups = $this->missed()
            ->selectRaw(self::METHOD_SQL.' AS method, '.self::PATH_SQL.' AS path, COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources, MAX(occurred_at) AS last_seen')
            ->groupBy('method', 'path')
            ->orderByDesc('sources')->orderByDesc('hits')
            ->limit(self::ROWS)
            ->get();

        // Each path's commonest query string, and how many different ones it had.
        $queries = $this->missed()
            ->whereIn(DB::raw(self::PATH_SQL), $groups->pluck('path')->all())
            ->whereRaw("COALESCE(json_extract(raw, '$.query'), '') <> ''")
            ->selectRaw(self::METHOD_SQL.' AS method, '.self::PATH_SQL." AS path, json_extract(raw, '$.query') AS query, COUNT(*) AS n")
            ->groupBy('method', 'path', 'query')
            ->orderByDesc('n')
            ->get()
            ->groupBy(fn ($r): string => $r->method.' '.$r->path);

        return [
            'days' => self::DAYS,
            'hits' => (int) $totals->hits,
            'sources' => (int) $totals->sources,
            'rows' => $groups->map(function ($r) use ($queries): array {
                $forPath = $queries->get($r->method.' '.$r->path);
                $query = $forPath?->first()?->query;

                return [
                    'method' => (string) $r->method,
                    'path' => (string) $r->path,
                    'hits' => (int) $r->hits,
                    'sources' => (int) $r->sources,
                    'last_seen' => Carbon::parse($r->last_seen)->diffForHumans(),
                    'query' => $query,
                    'queries' => $forPath?->count() ?? 0,
                    // What it's after, for the row's definition.
                    'explain' => $this->probes->explain((string) $r->method, (string) $r->path, $query),
                    'filter' => self::filter((string) $r->method, (string) $r->path),
                ];
            })->values()->all(),
        ];
    }

    /**
     * The stream filter that shows one row's requests: missed()'s conditions
     * in the filter language, so clicking "/" shows its probes and not every
     * visit to the home page. Keep the two in step (DashboardTest checks).
     */
    public static function filter(string $method, string $path): string
    {
        return implode(' && ', [
            'site == decoy',
            'path == '.DisplayFilter::quote($path),
            'method == '.DisplayFilter::quote($method),
            'sig in {benign scanner_ua}',
            ...(in_array($method, ['GET', 'HEAD'], true) ? ['(query != "" || !(status in {200 503}))'] : []),
        ]);
    }

    /**
     * @return Builder<Event>
     */
    private function missed(): Builder
    {
        return Event::query()
            ->where('source', 'honeypot_http')
            ->where('occurred_at', '>=', now()->subDays(self::DAYS))
            ->whereRaw(Event::SIGNATURE_SQL." IN ('benign', 'scanner_ua')")
            ->where(fn (Builder $q) => $q
                ->whereRaw("COALESCE(json_extract(raw, '$.status'), 200) NOT IN (200, 503)")
                ->orWhereRaw("COALESCE(json_extract(raw, '$.query'), '') <> ''")
                ->orWhereRaw(self::METHOD_SQL." NOT IN ('GET', 'HEAD')"));
    }
}
