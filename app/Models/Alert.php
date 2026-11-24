<?php

namespace App\Models;

use Database\Factories\AlertFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    /** @use HasFactory<AlertFactory> */
    use HasFactory;

    protected $fillable = [
        'rule', 'severity', 'title', 'src_ip', 'dst_ip', 'host',
        'first_seen_at', 'last_seen_at', 'event_count', 'details', 'status',
    ];

    /**
     * Alerts nobody has acknowledged or resolved yet.
     *
     * @param  Builder<Alert>  $query
     */
    public function scopeOpen(Builder $query): void
    {
        $query->where('status', 'open');
    }

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'details' => 'array',
        ];
    }
}
