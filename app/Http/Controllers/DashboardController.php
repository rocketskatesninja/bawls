<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\Sensor;
use App\Services\Bans;
use App\Services\EventStream;
use App\Services\OverviewWindow;
use App\Services\ProbeDigest;
use App\Services\TrafficChart;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The overview page. Each panel's data comes from the service that owns it;
 * this only reads the request and names the props.
 */
class DashboardController extends Controller
{
    /** The alerts panel lists at most this many open alerts. */
    private const OPEN_ALERTS = 25;

    public function __construct(
        private EventStream $stream,
        private TrafficChart $chart,
        private OverviewWindow $window,
        private ProbeDigest $digest,
    ) {}

    public function overview(Request $request): Response
    {
        $range = TrafficChart::range($request->string('range')->toString());

        // Every prop is a closure, so a partial reload (a page change, a range
        // switch, the live refresh) works out only the props it asks for. The
        // stats and chart deliberately ignore the stream's filter: the totals
        // stay a fixed reference point while you narrow the list.
        return Inertia::render('Overview', [
            'stats' => fn (): array => $this->window->stats(),
            'range' => $range,
            'traffic' => fn (): array => $this->chart->byHour($range),
            'stream' => fn (): array => $this->stream->page(
                $request->string('f')->toString(),
                $request->integer('page', 1),
                $request->integer('per', EventStream::PER_PAGE),
            ),
            'openAlerts' => fn (): array => $this->openAlerts(),
            'topSources' => fn (): array => $this->window->topSources(),
            'sensors' => fn (): array => $this->sensors(),
            'aggregates' => fn (): array => $this->window->aggregates(),
            'attackMap' => fn (): array => $this->window->attackMap(),
            // A week of data: the live refresh never asks for it.
            'unrecognised' => fn (): array => $this->digest->all(),
        ]);
    }

    /**
     * @return list<array{id: int, rule: string, severity: int, title: string, src_ip: string|null, event_count: int, last_seen: string|null, banned: bool}>
     */
    private function openAlerts(): array
    {
        return Alert::open()
            ->orderByDesc('severity')
            ->orderByDesc('last_seen_at')
            ->limit(self::OPEN_ALERTS)
            ->get()
            ->map(fn (Alert $alert): array => [
                'id' => $alert->id,
                'rule' => $alert->rule,
                'severity' => $alert->severity,
                'title' => $alert->title,
                'src_ip' => $alert->src_ip,
                'event_count' => $alert->event_count,
                'last_seen' => $alert->last_seen_at?->diffForHumans(),
                // Whether fail2ban is holding the address right now (the console's
                // copy of its bans), so a ban shows on the alert the moment it lands.
                'banned' => $alert->src_ip !== null && Bans::find($alert->src_ip) !== null,
            ])
            ->all();
    }

    /**
     * @return list<array{name: string, online: bool, last_seen: string|null, events: int}>
     */
    private function sensors(): array
    {
        return Sensor::orderBy('name')
            ->get()
            ->map(fn (Sensor $sensor): array => [
                'name' => $sensor->name,
                'online' => $sensor->isOnline(),
                'last_seen' => $sensor->last_seen_at?->diffForHumans(),
                'events' => $sensor->events_received,
            ])
            ->all();
    }
}
