<?php

namespace App\Services;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use Illuminate\Support\Carbon;

/**
 * The overview's "last 24 hours" panels: the stat tiles, top sources, what
 * the decoy is drawing, and the attack map. They share one window so their
 * figures agree with each other and with the chart beside them.
 */
class OverviewWindow
{
    /** The attack map shows at most this many places. */
    private const MAP_POINTS = 400;

    /**
     * The window starts on an hour boundary, like the chart's first bar,
     * rather than a rolling 24 hours.
     */
    public function start(): Carbon
    {
        return now()->subHours(23)->startOfHour();
    }

    /**
     * @return array{events_24h: int, events_total: int, alerts_open: int, alerts_critical: int, sensors_online: int, sensors_total: int, blocked_24h: int, decoy_24h: int}
     */
    public function stats(): array
    {
        $day = Event::where('occurred_at', '>=', $this->start())
            ->selectRaw("COUNT(*) AS events, SUM(action = 'blocked') AS blocked, SUM(source = 'honeypot_http') AS decoy")
            ->first();

        return [
            'events_24h' => (int) $day->events,
            'events_total' => Event::count(),
            'alerts_open' => Alert::open()->count(),
            'alerts_critical' => Alert::open()->where('severity', '>=', 4)->count(),
            'sensors_online' => Sensor::where('last_seen_at', '>', now()->subMinutes(Sensor::ONLINE_MINUTES))->count(),
            'sensors_total' => Sensor::count(),
            'blocked_24h' => (int) $day->blocked,
            'decoy_24h' => (int) $day->decoy,
        ];
    }

    /**
     * @return list<array{ip: string, hits: int, ports: int}>
     */
    public function topSources(): array
    {
        return Event::where('occurred_at', '>=', $this->start())
            ->selectRaw('src_ip, COUNT(*) AS hits, COUNT(DISTINCT dst_port) AS ports')
            // "+src_ip" tells SQLite not to group by walking the whole
            // (src_ip, occurred_at) index, which covers every event ever
            // kept; it uses the time index and reads only this window.
            ->groupByRaw('+src_ip')
            ->orderByDesc('hits')
            ->limit(10)
            ->get()
            ->map(fn ($row): array => ['ip' => $row->src_ip, 'hits' => (int) $row->hits, 'ports' => (int) $row->ports])
            ->all();
    }

    /**
     * What the decoy is drawing: most-probed paths, signature mix, and where
     * the sources sit.
     *
     * @return array{paths: list<array{path: string, hits: int}>, signatures: list<array{signature: string, hits: int}>, countries: list<array{country: string, n: int}>}
     */
    public function aggregates(): array
    {
        $since = $this->start();
        $decoy = fn () => Event::query()->where('occurred_at', '>=', $since)->where('source', 'honeypot_http');

        // Flood-cap summaries carry a placeholder path, "(suppressed flood)",
        // not a URL anyone requested, so they're left out of the path ranking.
        $paths = $decoy()
            ->whereRaw(Event::SIGNATURE_SQL.' <> ?', ['flood'])
            ->selectRaw("json_extract(raw, '$.path') AS path, COUNT(*) AS hits")
            ->groupBy('path')->orderByDesc('hits')->limit(8)->get()
            ->map(fn ($r): array => ['path' => $r->path, 'hits' => (int) $r->hits])->all();

        $signatures = $decoy()
            ->selectRaw(Event::SIGNATURE_SQL.' AS sig, COUNT(*) AS hits')
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
     * Where the window's traffic came from, for the attack map: each place
     * (enriched addresses, rounded to a tenth of a degree) with its worst
     * kind of event. Only enriched addresses have a location, and ordinary
     * visitors are never enriched, so this maps attackers and firewall
     * knockers, not people browsing the site.
     *
     * @return list<array{lat: float, lng: float, country: string|null, city: string|null, addresses: int, events: int, kind: string, last_seen: string}>
     */
    public function attackMap(): array
    {
        return Event::query()
            ->join('ip_intel', 'ip_intel.ip', '=', 'events.src_ip')
            ->where('events.occurred_at', '>=', $this->start())
            ->where('ip_intel.is_private', false)
            ->whereNotNull('ip_intel.latitude')
            ->whereNotNull('ip_intel.longitude')
            ->selectRaw('ROUND(ip_intel.latitude, 1) AS lat, ROUND(ip_intel.longitude, 1) AS lng')
            ->selectRaw('MAX(ip_intel.country) AS country, MAX(ip_intel.city) AS city')
            ->selectRaw('COUNT(DISTINCT events.src_ip) AS addresses, COUNT(*) AS events')
            ->selectRaw('MIN('.Event::kindRankSql().') AS worst, MAX(events.occurred_at) AS last_seen')
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
}
