<?php

namespace App\Models;

use Database\Factories\EventFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Event extends Model
{
    /** @use HasFactory<EventFactory> */
    use HasFactory;

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

    public $timestamps = false;

    protected $fillable = [
        'occurred_at', 'sensor_id', 'host', 'source', 'direction', 'proto',
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'iface', 'action',
        'pid', 'process', 'bytes', 'packets', 'raw',
    ];

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

    /** What the stream colours this event as: exploit, login, scan, page, firewall or other. */
    public function kind(): string
    {
        if (! $this->isHttp()) {
            return $this->action === 'blocked' ? 'firewall' : 'other';
        }
        $signature = $this->raw['signature'] ?? 'benign';

        return match (true) {
            in_array($signature, self::EXPLOIT_SIGNATURES, true) => 'exploit',
            $signature === 'login' || ($this->raw['login_attempt'] ?? false) => 'login',
            in_array($signature, self::SCAN_SIGNATURES, true) => 'scan',
            default => 'page',
        };
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
            $this->process,
            $this->iface,
        ]));
    }
}
