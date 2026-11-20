<?php

namespace App\Services;

use App\Models\Alert;
use App\Models\Event;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;

/**
 * Scans recent events for attack patterns and records alerts.
 *
 * Each rule aggregates a sliding window and fires when a source crosses its
 * configured threshold. An ongoing attack updates its existing open alert
 * rather than creating one per run, so a scan lasting an hour is one row.
 */
class AlertDetector
{
    /** @var array<int, string> Rules run in order, most specific first. */
    private const RULES = ['port_scan', 'host_sweep', 'brute_force', 'flood', 'web_exploit', 'web_scan'];

    public function run(): int
    {
        $recorded = 0;

        foreach (self::RULES as $rule) {
            if (! config("bawls.rules.{$rule}.enabled")) {
                continue;
            }

            $recorded += match ($rule) {
                'port_scan' => $this->portScan(),
                'host_sweep' => $this->hostSweep(),
                'brute_force' => $this->bruteForce(),
                'flood' => $this->flood(),
                'web_exploit' => $this->webExploit(),
                'web_scan' => $this->webScan(),
            };
        }

        return $recorded;
    }

    /** One source touching many distinct ports on a single host. */
    private function portScan(): int
    {
        $config = config('bawls.rules.port_scan');

        $hits = $this->windowed('port_scan')
            ->whereNotNull('dst_port')
            ->selectRaw('src_ip, dst_ip, host, COUNT(DISTINCT dst_port) AS ports, COUNT(*) AS events')
            ->groupBy('src_ip', 'dst_ip', 'host')
            ->havingRaw('COUNT(DISTINCT dst_port) >= ?', [$config['distinct_ports']])
            ->get();

        return $this->record($hits, 'port_scan', $config['severity'],
            fn ($hit): string => "Port scan: {$hit->src_ip} probed {$hit->ports} ports on {$hit->dst_ip}",
            fn ($hit): array => ['distinct_ports' => (int) $hit->ports, 'target' => $hit->dst_ip],
        );
    }

    /** One source touching many distinct hosts — horizontal sweep. */
    private function hostSweep(): int
    {
        $config = config('bawls.rules.host_sweep');

        $hits = $this->windowed('host_sweep')
            ->selectRaw('src_ip, host, COUNT(DISTINCT dst_ip) AS hosts, COUNT(*) AS events')
            ->groupBy('src_ip', 'host')
            ->havingRaw('COUNT(DISTINCT dst_ip) >= ?', [$config['distinct_hosts']])
            ->get();

        return $this->record($hits, 'host_sweep', $config['severity'],
            fn ($hit): string => "Host sweep: {$hit->src_ip} contacted {$hit->hosts} hosts",
            fn ($hit): array => ['distinct_hosts' => (int) $hit->hosts],
        );
    }

    /** Repeated hits against authentication-bearing ports. */
    private function bruteForce(): int
    {
        $config = config('bawls.rules.brute_force');

        $hits = $this->windowed('brute_force')
            ->whereIn('dst_port', $config['ports'])
            ->selectRaw('src_ip, dst_ip, dst_port, host, COUNT(*) AS events')
            ->groupBy('src_ip', 'dst_ip', 'dst_port', 'host')
            ->havingRaw('COUNT(*) >= ?', [$config['attempts']])
            ->get();

        return $this->record($hits, 'brute_force', $config['severity'],
            fn ($hit): string => "Brute force: {$hit->events} attempts from {$hit->src_ip} on port {$hit->dst_port}",
            fn ($hit): array => ['port' => (int) $hit->dst_port, 'attempts' => (int) $hit->events],
        );
    }

    /**
     * High event volume from one source. Grouped by destination first so
     * ignored traffic (multicast chatter) can be dropped before summing,
     * then folded back to a per-source total.
     */
    private function flood(): int
    {
        $config = config('bawls.rules.flood');

        $perDestination = $this->windowed('flood')
            ->selectRaw('src_ip, dst_ip, host, COUNT(*) AS events')
            ->groupBy('src_ip', 'dst_ip', 'host')
            ->get();

        $hits = $this->rejectIgnored($perDestination)
            ->groupBy('src_ip')
            ->map(fn (Collection $rows) => (object) [
                'src_ip' => $rows->first()->src_ip,
                'dst_ip' => null,
                'host' => $rows->first()->host,
                'events' => $rows->sum('events'),
                'first_at' => $rows->min('first_at'),
                'last_at' => $rows->max('last_at'),
            ])
            ->filter(fn ($hit): bool => $hit->events >= $config['events'])
            ->values();

        return $this->record($hits, 'flood', $config['severity'],
            fn ($hit): string => "Traffic flood: {$hit->events} events from {$hit->src_ip}",
            fn ($hit): array => ['events_in_window' => (int) $hit->events],
        );
    }

    /**
     * Any high-risk exploit signature against the decoy. One hit is enough, so
     * it fires immediately and accumulates into a single alert per source.
     */
    private function webExploit(): int
    {
        $config = config('bawls.rules.web_exploit');

        $hits = $this->windowed('web_exploit')
            ->where('source', 'honeypot_http')
            ->whereIn('raw->signature', $config['signatures'])
            ->selectRaw('src_ip, host, COUNT(*) AS events')
            ->groupBy('src_ip', 'host')
            ->get();

        return $this->record($hits, 'web_exploit', $config['severity'],
            fn ($hit): string => "Exploit attempt: {$hit->events} on the decoy from {$hit->src_ip}",
            fn ($hit): array => ['attempts' => (int) $hit->events],
        );
    }

    /** One source requesting many distinct decoy paths — scanning the website. */
    private function webScan(): int
    {
        $config = config('bawls.rules.web_scan');

        $hits = $this->windowed('web_scan')
            ->where('source', 'honeypot_http')
            ->selectRaw('src_ip, host, COUNT(DISTINCT json_extract(raw, \'$.path\')) AS paths, COUNT(*) AS events')
            ->groupBy('src_ip', 'host')
            ->havingRaw('COUNT(DISTINCT json_extract(raw, \'$.path\')) >= ?', [$config['distinct_paths']])
            ->get();

        return $this->record($hits, 'web_scan', $config['severity'],
            fn ($hit): string => "Web scan: {$hit->src_ip} hit {$hit->paths} decoy paths",
            fn ($hit): array => ['distinct_paths' => (int) $hit->paths],
        );
    }

    /**
     * Base query for a rule's window: inbound events only. Every rule groups
     * these, and record() needs each group's first and last sighting.
     */
    private function windowed(string $rule): Builder
    {
        $window = config("bawls.rules.{$rule}.window");

        return Event::query()
            ->where('occurred_at', '>=', now()->subSeconds($window))
            ->where('direction', 'in')
            ->selectRaw('MIN(occurred_at) AS first_at, MAX(occurred_at) AS last_at');
    }

    /**
     * Drop rows whose source or destination sits in a configured ignore CIDR.
     *
     * @param  Collection<int, object>  $hits
     * @return Collection<int, object>
     */
    private function rejectIgnored(Collection $hits): Collection
    {
        $ignoreDst = config('bawls.ignore.dst', []);
        $ignoreSrc = config('bawls.ignore.src', []);

        return $hits->reject(fn ($hit): bool => (isset($hit->dst_ip) && Network::inAny($hit->dst_ip, $ignoreDst))
            || Network::inAny($hit->src_ip, $ignoreSrc))->values();
    }

    /**
     * Upsert one alert per (rule, src_ip) that isn't resolved, so a sustained
     * attack accumulates into a single row instead of one per detector run.
     * An acknowledged alert keeps accumulating quietly (it stays acked); only a
     * resolved one lets a returning attacker open a fresh alert. Ignored
     * sources are dropped here, so the ignore list covers every rule.
     *
     * @param  Collection<int, object>  $hits
     */
    private function record(Collection $hits, string $rule, int $severity, callable $title, callable $details): int
    {
        $hits = $this->rejectIgnored($hits);

        foreach ($hits as $hit) {
            $existing = Alert::where('rule', $rule)
                ->where('src_ip', $hit->src_ip)
                ->where('status', '!=', 'resolved')
                ->first();

            $attributes = [
                'severity' => $severity,
                'title' => $title($hit),
                'dst_ip' => $hit->dst_ip ?? null,
                'host' => $hit->host,
                'last_seen_at' => Carbon::parse($hit->last_at),
                'event_count' => (int) $hit->events,
                'details' => $details($hit),
            ];

            if ($existing) {
                // New activity on an open alert re-requests the ban, so an
                // attacker returning after it expires is dropped again.
                $active = $existing->last_seen_at === null
                    || $attributes['last_seen_at']->gt($existing->last_seen_at);
                $existing->fill($attributes)->save();

                if ($active) {
                    Blocklist::ban($existing);
                }

                continue;
            }

            $alert = Alert::create($attributes + [
                'rule' => $rule,
                'src_ip' => $hit->src_ip,
                'first_seen_at' => Carbon::parse($hit->first_at),
                'status' => 'open',
            ]);

            $this->notify($alert);
            Blocklist::ban($alert);
        }

        return $hits->count();
    }

    /** POST a newly-raised, high-severity alert to the configured webhook. */
    private function notify(Alert $alert): void
    {
        $webhook = config('bawls.alert.webhook');
        if (! $webhook || $alert->severity < (int) config('bawls.alert.min_severity')) {
            return;
        }

        try {
            Http::timeout(5)->post($webhook, [
                'rule' => $alert->rule,
                'severity' => $alert->severity,
                'title' => $alert->title,
                'src_ip' => $alert->src_ip,
                'host' => $alert->host,
            ]);
        } catch (\Throwable) {
            // A down or slow webhook must never break detection.
        }
    }
}
