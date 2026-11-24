<?php

namespace App\Models;

use Database\Factories\SensorFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Sensor extends Model
{
    /** @use HasFactory<SensorFactory> */
    use HasFactory;

    /**
     * What each kind of sensor may report. A sensor's token only vouches for
     * its own kind of event, so a compromised decoy can't post "an exploit
     * on a real site" or a firewall block. bawls installs the first three;
     * the rest are tripwire's (the project this grew from), listed so the
     * ingest format the two share stays whole. Nothing here sends them.
     *
     * @var array<string, list<string>>
     */
    public const SOURCES = [
        'honeypot' => ['honeypot_http'],
        'sites' => ['site_http'],
        'ufw' => ['ufw_block'],
        'ebpf' => ['ebpf_connect', 'ebpf_accept'],
        'mirror' => ['mirror_flow'],
        'sshd' => ['sshd_auth'],
    ];

    /** A sensor that reported within this many minutes counts as online. */
    public const ONLINE_MINUTES = 5;

    protected $fillable = ['name', 'host', 'kind', 'token_hash', 'enabled'];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return [
            'last_seen_at' => 'datetime',
            'enabled' => 'boolean',
            'events_received' => 'integer',
        ];
    }

    public function isOnline(): bool
    {
        return $this->last_seen_at?->gt(now()->subMinutes(self::ONLINE_MINUTES)) ?? false;
    }

    /** May this sensor report events from this source? */
    public function mayReport(string $source): bool
    {
        return in_array($source, self::SOURCES[$this->kind] ?? [], true);
    }

    public function events(): HasMany
    {
        return $this->hasMany(Event::class);
    }
}
