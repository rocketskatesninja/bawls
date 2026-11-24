<?php

namespace App\Models;

use Database\Factories\EventFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Event extends Model
{
    /** @use HasFactory<EventFactory> */
    use HasFactory;

    /**
     * Every signature an event can carry, worst first. The sensors assign
     * them (SIGNATURES in sensors/signatures.py); SignatureParityTest fails
     * if the two lists drift apart. The groups below are slices of this.
     */
    public const SIGNATURES = [
        'cve_probe', 'rce', 'sqli', 'traversal', 'login', 'dirbust', 'scanner_ua', 'flood', 'browser_check', 'benign',
    ];

    /**
     * Decoy signatures that say nothing bad about the sender: ordinary page
     * views, and people who opted into the disclosed /browser-check test.
     * Their IPs are never enriched and their events expire on the short
     * retention window.
     */
    public const HARMLESS_SIGNATURES = ['benign', 'browser_check'];

    /** Decoy signatures that carry an attack payload. */
    public const EXPLOIT_SIGNATURES = ['cve_probe', 'rce', 'sqli', 'traversal'];

    /** Decoy signatures of tools mapping the site rather than attacking it. */
    public const SCAN_SIGNATURES = ['dirbust', 'scanner_ua', 'flood'];

    /** HTTP requests: hits on the decoy, and exploit attempts on your real sites. */
    public const HTTP_SOURCES = ['honeypot_http', 'site_http'];

    /**
     * A sign-in attempt on the decoy, as SQL: a POST to a login path, whatever
     * it is labelled (one carrying a payload is labelled sqli and is still a
     * sign-in). The decoy flags these; the signature arm is for events from
     * before it did (2026-11-18) and can go once those have aged out, after
     * 2027-05-17. isLoginAttempt() is the same test in PHP.
     */
    public const LOGIN_ATTEMPT_SQL = "(json_extract(raw, '$.login_attempt') = 1 OR json_extract(raw, '$.signature') = 'login')";

    /**
     * An event's signature as SQL, for showing and grouping. `signature` is
     * an indexed column generated from raw.signature (see its migration):
     * test that column directly (where('signature', ...)) when filtering,
     * so the index is used. Every sensor labels what it sends; the fallback
     * here only covers an HTTP event stored without a label, which counts as
     * an ordinary page view, as kind() and summary() treat it.
     */
    public const SIGNATURE_SQL = "COALESCE(events.signature, 'benign')";

    /**
     * A request a browser made on behalf of another site's page (the sensors'
     * is_cross_site, sensors/signatures.py), as SQL. These are recorded and
     * alerted like any other, but never ban: the sender may be an innocent
     * visitor to a page that embeds the URL.
     */
    public const CROSS_SITE_SQL = "(COALESCE(json_extract(raw, '$.cross_site'), 0) = 1)";

    /** What kind() can return, worst first. */
    public const KINDS = ['exploit', 'login', 'scan', 'page', 'firewall', 'other'];

    public $timestamps = false;

    protected $fillable = [
        'occurred_at', 'sensor_id', 'host', 'source', 'direction', 'proto',
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'iface', 'action',
        'pid', 'process', 'bytes', 'packets', 'raw',
    ];

    /** The generated column repeats raw.signature; exports show it once, inside raw. */
    protected $hidden = ['signature'];

    protected function casts(): array
    {
        return [
            'occurred_at' => 'datetime',
            'raw' => 'array',
        ];
    }

    public function sensor(): BelongsTo
    {
        return $this->belongsTo(Sensor::class);
    }

    /** A request to the decoy or to one of your real sites (not a packet). */
    public function isHttp(): bool
    {
        return in_array($this->source, self::HTTP_SOURCES, true);
    }

    /** A sign-in attempt on the decoy (see LOGIN_ATTEMPT_SQL). */
    public function isLoginAttempt(): bool
    {
        return (bool) ($this->raw['login_attempt'] ?? false) || ($this->raw['signature'] ?? null) === 'login';
    }

    /**
     * @param  Builder<Event>  $query
     */
    public function scopeLoginAttempts(Builder $query): void
    {
        $query->where('source', 'honeypot_http')->whereRaw(self::LOGIN_ATTEMPT_SQL);
    }

    /** What the stream colours this event as: exploit, login, scan, page, firewall or other. */
    public function kind(): string
    {
        if (! $this->isHttp()) {
            return $this->action === 'blocked' ? 'firewall' : 'other';
        }
        $signature = $this->raw['signature'] ?? 'benign';

        return match (true) {
            in_array($signature, self::EXPLOIT_SIGNATURES, true) => 'exploit',
            $this->isLoginAttempt() => 'login',
            in_array($signature, self::SCAN_SIGNATURES, true) => 'scan',
            default => 'page',
        };
    }

    /**
     * kind() as a SQLite expression, so a query can count events by kind.
     * Built from the same lists, and tested against kind(), so the two agree.
     */
    public static function kindSql(): string
    {
        $list = fn (array $values): string => "'".implode("', '", $values)."'";
        $signature = "json_extract(raw, '$.signature')";

        return 'CASE'
            .' WHEN source NOT IN ('.$list(self::HTTP_SOURCES).") THEN CASE WHEN action = 'blocked' THEN 'firewall' ELSE 'other' END"
            ." WHEN {$signature} IN (".$list(self::EXPLOIT_SIGNATURES).") THEN 'exploit'"
            .' WHEN '.self::LOGIN_ATTEMPT_SQL." THEN 'login'"
            ." WHEN {$signature} IN (".$list(self::SCAN_SIGNATURES).") THEN 'scan'"
            ." ELSE 'page' END";
    }

    /** kind()'s position in KINDS as SQL (0 is the worst), for "the worst kind seen". */
    public static function kindRankSql(): string
    {
        $rank = 'CASE '.self::kindSql();
        foreach (self::KINDS as $position => $kind) {
            $rank .= " WHEN '{$kind}' THEN {$position}";
        }

        return $rank.' END';
    }

    /** "203.0.113.9:40000", or the bare address when the port isn't known. */
    public function sourceAddress(): string
    {
        return $this->src_ip.($this->src_port ? ':'.$this->src_port : '');
    }

    public function destinationAddress(): string
    {
        return $this->dst_ip.($this->dst_port ? ':'.$this->dst_port : '');
    }

    /** The protocol as the stream shows it: HTTP for the decoy, else the packet's. */
    public function protocolLabel(): string
    {
        return $this->isHttp() ? 'HTTP' : strtoupper((string) $this->proto);
    }

    /**
     * The stream's Info column, Wireshark-style: the request and what it was
     * caught as (and, for a real site, which one), or what the firewall did
     * with the packet.
     */
    public function summary(): string
    {
        $raw = $this->raw ?? [];
        if ($this->isHttp()) {
            $query = (string) ($raw['query'] ?? '');
            $signature = $raw['signature'] ?? 'benign';

            return ($raw['method'] ?? '?').' '.($raw['path'] ?? '/').($query !== '' ? "?{$query}" : '')
                .(in_array($signature, self::HARMLESS_SIGNATURES, true) ? '' : " · {$signature}")
                .(isset($raw['status']) ? " → {$raw['status']}" : '')
                .(isset($raw['site']) ? " · {$raw['site']}" : '');
        }

        return implode(' · ', array_filter([
            trim(($this->dst_port ? "port {$this->dst_port} " : '').$this->action),
            $this->iface,
        ]));
    }
}
