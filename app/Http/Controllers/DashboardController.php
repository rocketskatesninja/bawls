<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Services\Bans;
use App\Services\DisplayFilter;
use App\Services\DisplayFilterError;
use App\Services\Settings;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

class DashboardController extends Controller
{
    public function __construct(private Settings $settings) {}

    /** The stream shows the newest 200 matches; Load older adds 200 at a time, up to 1,000. */
    private const STREAM_STEP = 200;

    private const STREAM_MAX = 1000;

    /** The events-per-hour chart's ranges, in hours. */
    private const RANGES = ['24h' => 24, '7d' => 168];

    /** How far back the unrecognised-probes digest looks, and how many rows it shows. */
    private const DIGEST_DAYS = 7;

    private const DIGEST_ROWS = 15;

    public function overview(Request $request): Response
    {
        $limit = (int) round($request->integer('limit', self::STREAM_STEP) / self::STREAM_STEP) * self::STREAM_STEP;
        $range = array_key_exists($request->string('range')->toString(), self::RANGES) ? $request->string('range')->toString() : '24h';

        return Inertia::render('Overview', [
            'stats' => $this->stats(),
            'range' => $range,
            'traffic' => $this->trafficByHour(self::RANGES[$range]),
            'stream' => $this->stream(
                trim($request->string('f')->toString()),
                max(self::STREAM_STEP, min(self::STREAM_MAX, $limit)),
            ),
            'openAlerts' => $this->openAlerts(),
            'topSources' => $this->topSources(),
            'sensors' => $this->sensors(),
            'aggregates' => $this->aggregates(),
            'attackMap' => $this->attackMap(),
            // A week of data: worked out on page load, not on every live refresh.
            'unrecognised' => fn (): array => $this->unrecognised(),
        ]);
    }

    /** The filter bar's as-you-type check: does this filter parse? */
    public function checkFilter(Request $request): JsonResponse
    {
        try {
            DisplayFilter::parse($request->string('f')->toString());
        } catch (DisplayFilterError $error) {
            return response()->json(['ok' => false, 'error' => ['message' => $error->getMessage(), 'at' => $error->position]]);
        }

        return response()->json(['ok' => true, 'error' => null]);
    }

    /**
     * The 24h figures must agree with the traffic chart beside them, so both
     * measure from the same hour boundary rather than a rolling 24 hours.
     */
    private function windowStart(): Carbon
    {
        return now()->subHours(23)->startOfHour();
    }

    /**
     * @return array<string, int|string|null>
     */
    private function stats(): array
    {
        $dayAgo = $this->windowStart();

        return [
            'events_24h' => Event::where('occurred_at', '>=', $dayAgo)->count(),
            'events_total' => Event::count(),
            'alerts_open' => Alert::where('status', 'open')->count(),
            'alerts_critical' => Alert::where('status', 'open')->where('severity', '>=', 4)->count(),
            'sensors_online' => Sensor::where('last_seen_at', '>=', now()->subMinutes(5))->count(),
            'sensors_total' => Sensor::count(),
            'blocked_24h' => Event::where('occurred_at', '>=', $dayAgo)->where('action', 'blocked')->count(),
            'decoy_24h' => Event::where('occurred_at', '>=', $dayAgo)->where('source', 'honeypot_http')->count(),
        ];
    }

    /**
     * Events bucketed by hour over the chart's range, zero-filled so the chart
     * shows quiet hours as gaps rather than collapsing them. Buckets are UTC
     * hours; each is labelled with its start in the display zone, so a
     * half-hour zone reads 07:30, 08:30, ... `from` and `to` are the bucket's
     * bounds in the display zone, as the stream filter's `time` reads them,
     * so clicking a bar can filter the stream to exactly that hour. Over 7
     * days the label carries the weekday too.
     *
     * @return array<int, array{hour: string, from: string, to: string, count: int, kinds: array<string, int>}>
     */
    private function trafficByHour(int $hours): array
    {
        // Counted by kind too, so each bar can show what its hour was made of.
        $counts = [];
        Event::where('occurred_at', '>=', now()->subHours($hours - 1)->startOfHour())
            ->selectRaw("strftime('%Y-%m-%dT%H', occurred_at) AS bucket, ".Event::kindSql().' AS kind, COUNT(*) AS count')
            ->groupBy('bucket', 'kind')
            ->get()
            ->each(function ($row) use (&$counts): void {
                $counts[$row->bucket][$row->kind] = (int) $row->count;
            });
        $none = array_fill_keys(Event::KINDS, 0);

        return collect(range($hours - 1, 0))
            ->map(function (int $hoursAgo) use ($counts, $hours, $none): array {
                $bucket = now()->subHours($hoursAgo)->format('Y-m-d\TH');
                $utc = Carbon::createFromFormat('!Y-m-d\TH', $bucket, 'UTC');
                $start = $this->settings->local($utc);
                $kinds = [...$none, ...($counts[$bucket] ?? [])];

                return [
                    'hour' => $start->format($hours > 24 ? 'D H:i' : 'H:i'),
                    'from' => $start->format('Y-m-d H:i'),
                    'to' => $this->settings->local($utc->copy()->addHour())->format('Y-m-d H:i'),
                    'count' => array_sum($kinds),
                    'kinds' => $kinds,
                ];
            })
            ->values()
            ->all();
    }

    /**
     * The event stream under its display filter (App\Services\DisplayFilter).
     * The stats and chart above it deliberately ignore the filter, so the
     * totals stay a fixed reference point while you narrow the list. A filter
     * that doesn't parse comes back as `error`, with no rows; the page keeps
     * showing its last good rows.
     *
     * @return array{filter: string, rows: list<array<string, mixed>>, matched: int, limit: int, error: array{message: string, at: int}|null}
     */
    private function stream(string $text, int $limit): array
    {
        $stream = ['filter' => $text, 'rows' => [], 'matched' => 0, 'limit' => $limit, 'error' => null];
        try {
            $filter = DisplayFilter::parse($text);
        } catch (DisplayFilterError $error) {
            return [...$stream, 'error' => ['message' => $error->getMessage(), 'at' => $error->position]];
        }

        $query = Event::query();
        $filter?->apply($query, $this->settings->timezone());

        return [
            ...$stream,
            'matched' => (clone $query)->count(),
            'rows' => $this->rows($query->latest('occurred_at')->latest('id')->limit($limit)),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function rows(Builder $query): array
    {
        return $query
            ->get(['id', 'occurred_at', 'source', 'proto', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'iface', 'action', 'process', 'raw'])
            ->map(fn (Event $event): array => [
                'id' => $event->id,
                'at' => $this->streamTime($event->occurred_at),
                'src' => $event->src_ip.($event->src_port ? ':'.$event->src_port : ''),
                'src_ip' => $event->src_ip,
                'dst' => $event->dst_ip.($event->dst_port ? ':'.$event->dst_port : ''),
                'proto' => $event->protocolLabel(),
                'info' => $event->summary(),
                'kind' => $event->kind(),
            ])
            ->all();
    }

    /**
     * The stream's Time: just the time for today (in the display zone), with
     * the date for anything older, so yesterday's 14:02 can't pass for today's.
     */
    private function streamTime(CarbonInterface $at): string
    {
        $local = $this->settings->local($at);

        return $local->isSameDay($this->settings->local(now())) ? $local->format('H:i:s') : $local->format('M j H:i:s');
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function openAlerts(): array
    {
        // Whether fail2ban is holding the address right now (the console's copy
        // of its bans), so a ban shows on the alert the moment it lands.
        $banned = array_flip(array_column(Bans::current()['bans'], 'ip'));

        return Alert::where('status', 'open')
            ->orderByDesc('severity')
            ->orderByDesc('last_seen_at')
            ->limit(25)
            ->get()
            ->map(fn (Alert $alert): array => [
                'id' => $alert->id,
                'rule' => $alert->rule,
                'severity' => $alert->severity,
                'title' => $alert->title,
                'src_ip' => $alert->src_ip,
                'event_count' => $alert->event_count,
                'last_seen' => $alert->last_seen_at?->diffForHumans(),
                'banned' => $alert->src_ip !== null && isset($banned[$alert->src_ip]),
            ])
            ->all();
    }

    /** The attack map shows at most this many places. */
    private const MAP_POINTS = 400;

    /**
     * Where the last 24 hours' traffic came from, for the attack map: each
     * place (enriched addresses, rounded to a tenth of a degree) with its
     * worst kind of event. Only enriched addresses have a location, and
     * ordinary visitors are never enriched, so this maps attackers and
     * firewall knockers, not people browsing the site.
     *
     * @return list<array{lat: float, lng: float, country: string|null, city: string|null, addresses: int, events: int, kind: string, last_seen: string}>
     */
    private function attackMap(): array
    {
        $rank = 'CASE '.Event::kindSql();
        foreach (Event::KINDS as $i => $kind) {
            $rank .= " WHEN '{$kind}' THEN {$i}";
        }
        $rank .= ' END';

        return Event::query()
            ->join('ip_intel', 'ip_intel.ip', '=', 'events.src_ip')
            ->where('events.occurred_at', '>=', $this->windowStart())
            ->where('ip_intel.is_private', false)
            ->whereNotNull('ip_intel.latitude')
            ->whereNotNull('ip_intel.longitude')
            ->selectRaw('ROUND(ip_intel.latitude, 1) AS lat, ROUND(ip_intel.longitude, 1) AS lng')
            ->selectRaw('MAX(ip_intel.country) AS country, MAX(ip_intel.city) AS city')
            ->selectRaw('COUNT(DISTINCT events.src_ip) AS addresses, COUNT(*) AS events')
            ->selectRaw("MIN({$rank}) AS worst, MAX(events.occurred_at) AS last_seen")
            ->groupBy('lat', 'lng')
            ->orderBy('worst')
            ->orderByDesc('events')
            ->limit(self::MAP_POINTS)
            ->get()
            ->map(fn ($row): array => [
                'lat' => (float) $row->lat,
                'lng' => (float) $row->lng,
                'country' => $row->country,
                'city' => $row->city,
                'addresses' => (int) $row->addresses,
                'events' => (int) $row->events,
                'kind' => Event::KINDS[(int) $row->worst],
                'last_seen' => (string) $row->last_seen,
            ])
            ->all();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function topSources(): array
    {
        return Event::where('occurred_at', '>=', $this->windowStart())
            ->select('src_ip', DB::raw('COUNT(*) AS hits'), DB::raw('COUNT(DISTINCT dst_port) AS ports'))
            ->groupBy('src_ip')
            ->orderByDesc('hits')
            ->limit(10)
            ->get()
            ->map(fn ($row): array => [
                'ip' => $row->src_ip,
                'hits' => (int) $row->hits,
                'ports' => (int) $row->ports,
            ])
            ->all();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function sensors(): array
    {
        return Sensor::orderBy('name')
            ->get()
            ->map(fn (Sensor $sensor): array => [
                'name' => $sensor->name,
                'online' => $sensor->last_seen_at?->gt(now()->subMinutes(5)) ?? false,
                'last_seen' => $sensor->last_seen_at?->diffForHumans(),
                'events' => (int) $sensor->events_received,
            ])
            ->all();
    }

    /**
     * What the decoy is drawing: most-probed paths, signature mix, and where
     * the sources sit — over the same 24h window as the stats.
     *
     * @return array<string, array<int, array<string, mixed>>>
     */
    private function aggregates(): array
    {
        $since = $this->windowStart();

        // Flood-cap summaries carry a placeholder path, "(suppressed flood)",
        // not a URL anyone requested, so they're left out of the path ranking.
        $paths = Event::query()
            ->where('occurred_at', '>=', $since)
            ->where('source', 'honeypot_http')
            ->whereRaw('COALESCE(json_extract(raw, \'$.signature\'), \'\') <> ?', ['flood'])
            ->selectRaw('json_extract(raw, \'$.path\') AS path, COUNT(*) AS hits')
            ->groupBy('path')->orderByDesc('hits')->limit(8)->get()
            ->map(fn ($r): array => ['path' => $r->path, 'hits' => (int) $r->hits])->all();

        $signatures = Event::query()
            ->where('occurred_at', '>=', $since)
            ->where('source', 'honeypot_http')
            // A page view the decoy left unlabelled counts as benign too, so the
            // two can't show up as two "benign" rows.
            ->selectRaw('COALESCE(json_extract(raw, \'$.signature\'), \'benign\') AS sig, COUNT(*) AS hits')
            ->groupBy('sig')->orderByDesc('hits')->get()
            ->map(fn ($r): array => ['signature' => $r->sig, 'hits' => (int) $r->hits])->all();

        $countries = IpIntel::query()
            ->whereNotNull('country')
            ->whereIn('ip', Event::select('src_ip')->where('occurred_at', '>=', $since))
            ->selectRaw('country, COUNT(*) AS n')
            ->groupBy('country')->orderByDesc('n')->limit(8)->get()
            ->map(fn ($r): array => ['country' => $r->country, 'n' => (int) $r->n])->all();

        return ['paths' => $paths, 'signatures' => $signatures, 'countries' => $countries];
    }

    /**
     * The weekly digest of what the signatures missed: decoy requests that
     * matched no pattern but look like probing, not browsing. That is an
     * unknown path (the decoy answered 404), a query string, a method other
     * than GET or HEAD, or a server error; plain page views are left out.
     * Grouped by method and path and ranked by how many addresses tried it,
     * so a new exploit probe stands out for adding to the sensor's patterns.
     *
     * @return array{days: int, hits: int, sources: int, rows: array<int, array{method: string, path: string, hits: int, sources: int, last_seen: string, query: ?string, queries: int}>}
     */
    private function unrecognised(): array
    {
        $method = "COALESCE(json_extract(raw, '$.method'), 'GET')";
        $path = "json_extract(raw, '$.path')";
        $missed = fn (): Builder => Event::query()
            ->where('source', 'honeypot_http')
            ->where('occurred_at', '>=', now()->subDays(self::DIGEST_DAYS))
            ->whereRaw("COALESCE(json_extract(raw, '$.signature'), 'benign') IN ('benign', 'scanner_ua')")
            ->where(fn (Builder $q) => $q
                ->whereRaw("COALESCE(json_extract(raw, '$.status'), 200) NOT IN (200, 503)")
                ->orWhereRaw("COALESCE(json_extract(raw, '$.query'), '') <> ''")
                ->orWhereRaw("{$method} NOT IN ('GET', 'HEAD')"));

        $totals = $missed()->selectRaw('COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources')->first();

        $groups = $missed()
            ->selectRaw("{$method} AS method, {$path} AS path, COUNT(*) AS hits, COUNT(DISTINCT src_ip) AS sources, MAX(occurred_at) AS last_seen")
            ->groupBy('method', 'path')
            ->orderByDesc('sources')->orderByDesc('hits')
            ->limit(self::DIGEST_ROWS)
            ->get();

        // Each path's commonest query string, and how many different ones it had.
        $queries = $missed()
            ->whereIn(DB::raw($path), $groups->pluck('path')->all())
            ->whereRaw("COALESCE(json_extract(raw, '$.query'), '') <> ''")
            ->selectRaw("{$method} AS method, {$path} AS path, json_extract(raw, '$.query') AS query, COUNT(*) AS n")
            ->groupBy('method', 'path', 'query')
            ->orderByDesc('n')
            ->get()
            ->groupBy(fn ($r): string => $r->method.' '.$r->path);

        return [
            'days' => self::DIGEST_DAYS,
            'hits' => (int) $totals->hits,
            'sources' => (int) $totals->sources,
            'rows' => $groups->map(function ($r) use ($queries): array {
                $forPath = $queries->get($r->method.' '.$r->path);

                return [
                    'method' => (string) $r->method,
                    'path' => (string) $r->path,
                    'hits' => (int) $r->hits,
                    'sources' => (int) $r->sources,
                    'last_seen' => Carbon::parse($r->last_seen)->diffForHumans(),
                    'query' => $forPath?->first()?->query,
                    'queries' => $forPath?->count() ?? 0,
                ];
            })->all(),
        ];
    }
}
