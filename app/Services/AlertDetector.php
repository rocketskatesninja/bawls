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
    /**
     * Each rule (its name in config/bawls.php and on its alerts) and the
     * method that runs it. A new rule needs an entry here, a config block,
     * and a line in Glossary::rule().
     *
     * @var array<string, string>
     */
    private const RULES = [
        'port_scan' => 'portScan',
        'brute_force' => 'bruteForce',
        'flood' => 'flood',
        'web_exploit' => 'webExploit',
        'web_scan' => 'webScan',
    ];

    /** Run every enabled rule; returns how many sources tripped one. */
    public function run(): int
    {
        $recorded = 0;
        foreach (self::RULES as $rule => $method) {
            if (config("bawls.rules.{$rule}.enabled")) {
                $recorded += $this->{$method}();
            }
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
     * ignored destinations (bawls.ignore.dst) can be dropped before summing,
     * then folded back to a per-source total.
     *
     * With the shipped limits this rarely fires: the decoy and the site
     * sensor each record at most 120 events a minute per address (the rest
     * become one "flood" summary event), and UFW rate-limits its own log.
     * It is the backstop for a sensor whose cap was raised or removed.
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
     * Any exploit signature (Event::EXPLOIT_SIGNATURES, the same list the
     * stream colours as an exploit) against the decoy or a real site. One hit is enough, so
     * it fires immediately and accumulates into a single alert per source.
     */
    private function webExploit(): int
    {
        $config = config('bawls.rules.web_exploit');

        // Every hit is recorded and alerted; these are the ones that may ban.
        // Not a request a browser made on behalf of another site's page (the
        // sender may be an innocent visitor to a page that embeds the URL),
        // and, during a watch period (BAWLS_SITE_BAN off), only decoy hits.
        $mayBan = 'NOT '.Event::CROSS_SITE_SQL.(Blocklist::siteBans() ? '' : " AND source = 'honeypot_http'");

        $hits = $this->windowed('web_exploit')
            ->whereIn('source', Event::HTTP_SOURCES)
            ->whereIn('signature', Event::EXPLOIT_SIGNATURES)
            ->selectRaw('src_ip, host, COUNT(*) AS events')
            ->selectRaw("SUM(source = 'honeypot_http') AS decoy_events")
            ->selectRaw('SUM('.Event::CROSS_SITE_SQL.') AS cross_site_events')
            ->selectRaw("MAX(CASE WHEN {$mayBan} THEN occurred_at END) AS ban_last_at")
            ->selectRaw("GROUP_CONCAT(DISTINCT json_extract(raw, '$.site')) AS sites")
            ->groupBy('src_ip', 'host')
            ->get();

        return $this->record($hits, 'web_exploit', $config['severity'],
            fn ($hit): string => "Exploit attempt: {$hit->events} on {$this->places($hit)} from {$hit->src_ip}",
            fn ($hit): array => [
                'attempts' => (int) $hit->events,
                'on_decoy' => (int) $hit->decoy_events,
                'on_sites' => $this->sites($hit),
                'cross_site' => (int) $hit->cross_site_events,
            ],
            // Ban only when a hit that may ban arrived since the alert last did.
            fn ($hit, ?Carbon $since): bool => $hit->ban_last_at !== null
                && ($since === null || Carbon::parse($hit->ban_last_at)->gt($since)),
        );
    }

    /**
     * The real sites an exploit hit came in on (the site log sensor's names).
     *
     * @return list<string>
     */
    private function sites(object $hit): array
    {
        $sites = array_filter(explode(',', (string) $hit->sites));
        sort($sites);

        return array_values($sites);
    }

    /** Where an exploit hit landed: "the decoy", "example.com", "the decoy and example.com". */
    private function places(object $hit): string
    {
        $places = [...($hit->decoy_events > 0 ? ['the decoy'] : []), ...$this->sites($hit)];
        $last = array_pop($places);

        return $places === [] ? (string) $last : implode(', ', $places)." and {$last}";
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
     * Turn a rule's hits into alerts: one per (rule, src_ip) that isn't
     * resolved, so a sustained attack accumulates into a single row instead
     * of one per detector run. Ignored sources are dropped here, so the
     * ignore list covers every rule.
     *
     * $bannable($hit, $since) can veto the ban for a hit (web_exploit's
     * watch period); $since is when the alert last saw activity, or null for
     * a new alert.
     *
     * @param  Collection<int, object>  $hits
     * @param  callable(object): string  $title
     * @param  callable(object): array<string, mixed>  $details
     * @param  (callable(object, ?Carbon): bool)|null  $bannable
     */
    private function record(Collection $hits, string $rule, int $severity, callable $title, callable $details, ?callable $bannable = null): int
    {
        $hits = $this->rejectIgnored($hits);

        foreach ($hits as $hit) {
            $attributes = [
                'severity' => $severity,
                'title' => $title($hit),
                'dst_ip' => $hit->dst_ip ?? null,
                'host' => $hit->host,
                'last_seen_at' => Carbon::parse($hit->last_at),
                'event_count' => (int) $hit->events,
                'details' => $details($hit),
            ];
            $existing = Alert::where('rule', $rule)
                ->where('src_ip', $hit->src_ip)
                ->where('status', '!=', 'resolved')
                ->first();

            $since = $existing?->last_seen_at;
            $alert = $existing
                ? $this->refresh($existing, $attributes)
                : $this->open($rule, $hit, $attributes);

            if ($alert && (! $bannable || $bannable($hit, $since))) {
                Blocklist::ban($alert);
            }
        }

        return $hits->count();
    }

    /**
     * Update an alert that is still open or acknowledged (an acknowledged one
     * keeps accumulating quietly). Returns it when there was new activity,
     * which re-requests the ban, so an attacker returning after a ban expired
     * is dropped again; null when nothing new happened.
     *
     * @param  array<string, mixed>  $attributes
     */
    private function refresh(Alert $alert, array $attributes): ?Alert
    {
        $since = $alert->last_seen_at;
        $alert->fill($attributes)->save();
        $active = $since === null || $alert->last_seen_at->gt($since);

        return $active ? $alert : null;
    }

    /**
     * Raise a new alert, unless a resolved one already covers these events.
     *
     * @param  array<string, mixed>  $attributes
     */
    private function open(string $rule, object $hit, array $attributes): ?Alert
    {
        // A resolved alert covers the requests it saw: those same requests,
        // still inside the rule's window, mustn't raise it again a minute
        // later. Only activity newer than it opens a fresh alert.
        $covered = Alert::where('rule', $rule)
            ->where('src_ip', $hit->src_ip)
            ->where('status', 'resolved')
            ->where('last_seen_at', '>=', $attributes['last_seen_at'])
            ->exists();
        if ($covered) {
            return null;
        }

        $alert = Alert::create($attributes + [
            'rule' => $rule,
            'src_ip' => $hit->src_ip,
            'first_seen_at' => Carbon::parse($hit->first_at),
            'status' => 'open',
        ]);
        $this->notify($alert);

        return $alert;
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
