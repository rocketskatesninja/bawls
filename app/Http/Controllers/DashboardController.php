<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Services\Settings;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Inertia\Inertia;
use Inertia\Response;

class DashboardController extends Controller
{
    public function __construct(private Settings $settings) {}

    public function overview(Request $request): Response
    {
        $filters = [
            'direction' => $request->string('direction')->toString() ?: 'all',
            'action' => $request->string('action')->toString() ?: 'all',
            'q' => $request->string('q')->toString(),
        ];

        return Inertia::render('Overview', [
            'stats' => $this->stats(),
            'traffic' => $this->trafficByHour(),
            'recentEvents' => $this->recentEvents($filters),
            'openAlerts' => $this->openAlerts(),
            'topSources' => $this->topSources(),
            'sensors' => $this->sensors(),
            'aggregates' => $this->aggregates(),
            'filters' => $filters,
        ]);
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
     * Events bucketed by hour for the last 24h, zero-filled so the chart
     * shows quiet hours as gaps rather than collapsing them. Buckets are UTC
     * hours; each is labelled with its start in the display zone, so a
     * half-hour zone reads 07:30, 08:30, ...
     *
     * @return array<int, array{hour: string, count: int}>
     */
    private function trafficByHour(): array
    {
        $counts = Event::where('occurred_at', '>=', $this->windowStart())
            ->selectRaw("strftime('%Y-%m-%dT%H', occurred_at) AS bucket, COUNT(*) AS count")
            ->groupBy('bucket')
            ->pluck('count', 'bucket');

        return collect(range(23, 0))
            ->map(function (int $hoursAgo) use ($counts): array {
                $bucket = now()->subHours($hoursAgo)->format('Y-m-d\TH');

                return [
                    'hour' => $this->settings->local(Carbon::createFromFormat('!Y-m-d\TH', $bucket, 'UTC'))->format('H:i'),
                    'count' => (int) ($counts[$bucket] ?? 0),
                ];
            })
            ->values()
            ->all();
    }

    /**
     * The event stream honours the header filters; the stats and chart
     * above it deliberately do not, so the totals stay a fixed reference
     * point while you narrow the list underneath them.
     *
     * @param  array<string, string>  $filters
     * @return array<int, array<string, mixed>>
     */
    private function recentEvents(array $filters): array
    {
        return Event::query()
            ->when($filters['direction'] !== 'all',
                fn (Builder $q) => $q->where('direction', $filters['direction']))
            ->when($filters['action'] !== 'all',
                fn (Builder $q) => $q->where('action', $filters['action']))
            ->when($filters['q'] !== '', function (Builder $q) use ($filters): void {
                $term = '%'.$filters['q'].'%';
                $q->where(fn (Builder $inner) => $inner
                    ->where('src_ip', 'like', $term)
                    ->orWhere('dst_ip', 'like', $term)
                    ->orWhere('process', 'like', $term));
            })
            ->latest('occurred_at')
            ->limit(60)
            ->get(['id', 'occurred_at', 'source', 'proto', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'action', 'process', 'raw'])
            ->map(fn (Event $event): array => [
                'id' => $event->id,
                'at' => $this->settings->local($event->occurred_at)->format('H:i:s'),
                'proto' => $event->proto,
                'src' => $event->src_ip.($event->src_port ? ':'.$event->src_port : ''),
                'src_ip' => $event->src_ip,
                'dst' => $event->dst_ip.($event->dst_port ? ':'.$event->dst_port : ''),
                'action' => $event->action,
                // For decoy hits the probed path is more use than a null process.
                'process' => $event->source === 'honeypot_http'
                    ? ($event->raw['path'] ?? null)
                    : $event->process,
            ])
            ->all();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function openAlerts(): array
    {
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
            ->selectRaw('json_extract(raw, \'$.signature\') AS sig, COUNT(*) AS hits')
            ->groupBy('sig')->orderByDesc('hits')->get()
            ->map(fn ($r): array => ['signature' => $r->sig ?? 'benign', 'hits' => (int) $r->hits])->all();

        $countries = IpIntel::query()
            ->whereNotNull('country')
            ->whereIn('ip', Event::select('src_ip')->where('occurred_at', '>=', $since))
            ->selectRaw('country, COUNT(*) AS n')
            ->groupBy('country')->orderByDesc('n')->limit(8)->get()
            ->map(fn ($r): array => ['country' => $r->country, 'n' => (int) $r->n])->all();

        return ['paths' => $paths, 'signatures' => $signatures, 'countries' => $countries];
    }
}
