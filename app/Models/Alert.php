<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Alert extends Model
{
    protected $fillable = [
        'rule', 'severity', 'title', 'src_ip', 'dst_ip', 'host',
        'first_seen_at', 'last_seen_at', 'event_count', 'details', 'status',
    ];

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'details' => 'array',
        ];
    }
}
