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
}
