<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Services\Bans;
use App\Services\Network;
use App\Services\Settings;
use App\Services\UserAgent;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Inertia\Inertia;
use Inertia\Response;

class IpController extends Controller
{
    public function __construct(private Settings $settings) {}

    /** Decoy signatures ordered by how much they matter, worst first. */
    private const SIGNATURE_RANK = [
        'cve_probe' => 7, 'rce' => 6, 'sqli' => 5, 'traversal' => 4,
        'login' => 3, 'dirbust' => 2, 'scanner_ua' => 1, 'benign' => 0,
    ];

    public function index(Request $request): Response
    {
        return $this->page($request, null);
    }

    public function show(Request $request, string $ip): Response
    {
        return $this->page($request, $ip);
    }

    private function page(Request $request, ?string $ip): Response
    {
        $filters = [
            'signature' => $request->string('signature')->toString(),
            'country' => $request->string('country')->toString(),
            'alerts' => $request->boolean('alerts'),
            'q' => $request->string('q')->toString(),
        ];

        return Inertia::render('IpDossier', [
            'ips' => $this->list($filters),
            'selected' => $ip ? $this->detail($ip) : null,
            'filters' => $filters,
        ]);
    }

    /**
     * The newest 300 external IPs seen in the last fortnight, with their intel
     * and the worst thing each did. Filters narrow the query *before* the cap,
     * so a match older than the newest 300 addresses is still found.
     *
     * @param  array<string, mixed>  $filters
     * @return Collection<int, array<string, mixed>>
     */
    private function list(array $filters): Collection
    {
        $since = now()->subDays(14);
        $unresolved = Alert::select('src_ip')->where('status', '!=', 'resolved');

        $seen = Event::query()
            ->where('occurred_at', '>=', $since)
            ->when($filters['q'] !== '', fn (Builder $q) => $q->where('src_ip', 'like', '%'.$filters['q'].'%'))
            ->when($filters['alerts'], fn (Builder $q) => $q->whereIn('src_ip', $unresolved))
            ->when($filters['country'] !== '', fn (Builder $q) => $q->whereIn('src_ip',
                IpIntel::select('ip')->where('country', strtoupper($filters['country']))))
            ->when($filters['signature'] !== '', fn (Builder $q) => $q->whereIn('src_ip',
                Event::select('src_ip')->whereIn('source', Event::HTTP_SOURCES)->where('occurred_at', '>=', $since)
                    ->where('raw->signature', $filters['signature'])))
            ->selectRaw('src_ip, COUNT(*) AS hits, MAX(occurred_at) AS last_seen')
            ->groupBy('src_ip')
            ->orderByDesc('last_seen')
            ->limit(300)
            ->get()
            ->reject(fn ($row): bool => Network::isInternal($row->src_ip));

        $ips = $seen->pluck('src_ip');
        $intel = IpIntel::whereIn('ip', $ips)->get()->keyBy('ip');
        $alerts = (clone $unresolved)->whereIn('src_ip', $ips)
            ->selectRaw('MAX(severity) AS severity')
            ->groupBy('src_ip')->get()->keyBy('src_ip');
        $signatures = $this->worstSignatures($ips, $since);

        return $seen
            ->map(function ($row) use ($intel, $alerts, $signatures): array {
                /** @var IpIntel|null $i */
                $i = $intel[$row->src_ip] ?? null;

                return [
                    'ip' => $row->src_ip,
                    'hits' => (int) $row->hits,
                    'last_seen' => Carbon::parse($row->last_seen)->diffForHumans(),
                    'country' => $i?->country,
                    'asn' => $i?->asn,
                    'greynoise' => $i?->greynoise_class,
                    'abuse_score' => $i?->abuse_score,
                    'tor' => (bool) $i?->tor_exit,
                    'lat' => $i?->latitude,
                    'lng' => $i?->longitude,
                    'signature' => $signatures[$row->src_ip] ?? null,
                    'alert_severity' => $alerts[$row->src_ip]->severity ?? null,
                ];
            })
            ->values();
    }

    /**
     * The worst decoy signature seen from each IP, from the distinct
     * (ip, signature) pairs rather than every event's full payload.
     *
     * @param  Collection<int, string>  $ips
     * @return Collection<string, string>
     */
    private function worstSignatures(Collection $ips, Carbon $since): Collection
    {
        return Event::query()
            ->whereIn('source', Event::HTTP_SOURCES)
            ->whereIn('src_ip', $ips)
            ->where('occurred_at', '>=', $since)
            ->selectRaw("src_ip, COALESCE(json_extract(raw, '$.signature'), 'benign') AS signature")
            ->distinct()
            ->get()
            ->groupBy('src_ip')
            ->map(fn (Collection $rows): string => $rows->pluck('signature')
                ->sortByDesc(fn (string $s): int => self::SIGNATURE_RANK[$s] ?? 0)
                ->first());
    }

    /**
     * The full workup for one IP: intel, what it sent, its timeline and alerts.
     *
     * @return array<string, mixed>|null
     */
    /**
     * The verdict in one line, worst first: banned or not, what it tried and
     * for how long, and what outside intel says when it's telling.
     *
     * @return list<array{text: string, tone: string}>
     */
    private function summary(string $ip, ?IpIntel $intel): array
    {
        $exploits = implode(',', array_fill(0, count(Event::EXPLOIT_SIGNATURES), '?'));
        $seen = Event::where('src_ip', $ip)
            ->selectRaw('COUNT(*) AS events, MIN(occurred_at) AS first_at, MAX(occurred_at) AS last_at')
            ->selectRaw("SUM(json_extract(raw, '$.signature') IN ({$exploits})) AS exploits", Event::EXPLOIT_SIGNATURES)
            ->selectRaw("SUM(json_extract(raw, '$.signature') = 'login' OR json_extract(raw, '$.login_attempt') = 1) AS logins")
            ->first();
        $ban = collect(Bans::current()['bans'])->firstWhere('ip', $ip);

        $exploitCount = (int) $seen->exploits;
        $loginCount = (int) $seen->logins;

        $parts = [];
        if ($ban) {
            $parts[] = ['text' => 'Banned until '.$this->settings->local($ban['expires_at'])->format('M j H:i'), 'tone' => 'alarm'];
        }
        if ($exploitCount > 0) {
            $parts[] = ['text' => $exploitCount.' exploit attempt'.($exploitCount === 1 ? '' : 's'), 'tone' => 'alarm'];
        }
        if ($loginCount > 0) {
            $parts[] = ['text' => $loginCount.' password guess'.($loginCount === 1 ? '' : 'es'), 'tone' => 'signal'];
        }
        $eventCount = (int) $seen->events;
        if ($eventCount === 1) {
            $parts[] = ['text' => '1 event', 'tone' => 'dim'];
        } elseif ($eventCount > 1) {
            $first = Carbon::parse($seen->first_at);
            $last = Carbon::parse($seen->last_at);
            $span = $first->diffInSeconds($last) < 60 ? 'within a minute' : 'over '.$first->diffForHumans($last, CarbonInterface::DIFF_ABSOLUTE, parts: 1);
            $parts[] = ['text' => "{$eventCount} events {$span}", 'tone' => 'dim'];
        }
        if (($intel?->abuse_score ?? 0) >= 25) {
            $parts[] = ['text' => "AbuseIPDB {$intel->abuse_score}%", 'tone' => $intel->abuse_score >= 50 ? 'alarm' : 'amber'];
        }
        if ($intel?->greynoise_class === 'malicious') {
            $parts[] = ['text' => 'GreyNoise: malicious', 'tone' => 'alarm'];
        } elseif ($intel?->greynoise_class === 'benign') {
            $parts[] = ['text' => 'GreyNoise: known benign scanner', 'tone' => 'dim'];
        }
        if ($intel?->tor_exit) {
            $parts[] = ['text' => 'Tor exit', 'tone' => 'amber'];
        }

        return $parts;
    }

    private function detail(string $ip): ?array
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $intel = IpIntel::where('ip', $ip)->first();
        $events = Event::where('src_ip', $ip)->latest('occurred_at')->limit(100)->get();
        $alerts = Alert::where('src_ip', $ip)->orderByDesc('last_seen_at')->get();
        $latestWeb = $events->firstWhere('source', 'honeypot_http');
        $activeFp = $events->first(fn (Event $e): bool => ! empty($e->raw['browser_fingerprint'] ?? null));

        return [
            'summary' => $this->summary($ip, $intel),
            'ip' => $ip,
            'browser' => $activeFp ? [
                'fingerprint' => $activeFp->raw['browser_fingerprint'],
                'signals' => $activeFp->raw['browser_signals'] ?? [],
                'when' => $activeFp->occurred_at->diffForHumans(),
            ] : null,
            'intel' => $intel ? [
                'country' => $intel->country,
                'city' => $intel->city,
                'lat' => $intel->latitude,
                'lng' => $intel->longitude,
                'asn' => $intel->asn,
                'as_org' => $intel->as_org,
                'rdns' => $intel->rdns,
                'greynoise' => $intel->greynoise_class,
                'abuse_score' => $intel->abuse_score,
                'abuse_reports' => $intel->abuse_reports,
                'abuse_contact' => $intel->abuse_contact,
                'tor_exit' => $intel->tor_exit,
                'open_ports' => $intel->open_ports,
                'is_private' => $intel->is_private,
                'checked_at' => $intel->checked_at?->diffForHumans(),
            ] : null,
            'client' => $latestWeb ? $this->client((array) $latestWeb->raw) : null,
            'timeline' => $events->map(fn (Event $e): array => [
                'at' => $this->settings->local($e->occurred_at)->format('M j H:i:s'),
                'action' => $e->action,
                'proto' => $e->proto,
                'dst_port' => $e->dst_port,
                'method' => $e->raw['method'] ?? null,
                'path' => $e->raw['path'] ?? null,
                'signature' => $e->raw['signature'] ?? null,
                'status' => $e->raw['status'] ?? null,
            ])->all(),
            'alerts' => $alerts->map(fn (Alert $a): array => [
                'rule' => $a->rule,
                'severity' => $a->severity,
                'title' => $a->title,
                'event_count' => $a->event_count,
                'last_seen' => $a->last_seen_at?->diffForHumans(),
                'status' => $a->status,
            ])->all(),
            'decoys' => $events->where('source', 'honeypot_http')
                ->map(fn (Event $e): ?string => $e->raw['decoy'] ?? null)
                ->filter()->unique()->values()->all(),
        ];
    }

    /**
     * What the client sent — passive request metadata only.
     *
     * @param  array<string, mixed>  $raw
     * @return array<string, mixed>
     */
    private function client(array $raw): array
    {
        $parsed = UserAgent::summarize($raw['user_agent'] ?? '');

        return [
            'user_agent' => $raw['user_agent'] ?? '',
            'parsed' => $parsed,
            'http_fingerprint' => $raw['http_fingerprint'] ?? null,
            'accept' => $raw['accept'] ?? null,
            'accept_encoding' => $raw['accept_encoding'] ?? null,
            'accept_language' => $raw['accept_language'] ?? null,
            'client_hints' => $raw['client_hints'] ?? [],
            'sec_fetch' => $raw['sec_fetch'] ?? [],
            'header_order' => $raw['header_order'] ?? [],
            'assessment' => $this->assess($raw, $parsed),
        ];
    }

    /**
     * Compare the claimed User-Agent against the request's shape. A tool that
     * fakes a browser UA usually omits the headers a real browser always sends
     * (Accept-Language, Accept-Encoding, client hints, fetch metadata). The
     * verdict (bot, spoofed or consistent) is what the page colours by.
     *
     * @param  array<string, mixed>  $raw
     * @param  array{label: string, browser: ?string, os: ?string, bot: bool}  $parsed
     * @return array{verdict: string, text: string}
     */
    private function assess(array $raw, array $parsed): array
    {
        if ($parsed['bot']) {
            return ['verdict' => 'bot', 'text' => "Automated client ({$parsed['label']}) — no browser disguise."];
        }

        $browserish = ($raw['accept_language'] ?? '') !== ''
            && ($raw['accept_encoding'] ?? '') !== ''
            && (! empty($raw['client_hints']) || ! empty($raw['sec_fetch']));

        return $browserish
            ? ['verdict' => 'consistent', 'text' => "Request shape is consistent with {$parsed['label']}."]
            : ['verdict' => 'spoofed', 'text' => "Claims {$parsed['label']}, but the request shape is missing headers a real browser sends — likely a spoofed User-Agent."];
    }
}
