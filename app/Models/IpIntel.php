<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class IpIntel extends Model
{
    protected $table = 'ip_intel';

    protected $fillable = [
        'ip', 'is_private', 'country', 'city', 'latitude', 'longitude',
        'asn', 'as_org', 'rdns', 'abuse_score', 'abuse_reports',
        'greynoise_class', 'open_ports', 'tor_exit', 'abuse_contact', 'checked_at',
    ];

    protected function casts(): array
    {
        return [
            'is_private' => 'boolean',
            'latitude' => 'float',
            'longitude' => 'float',
            'open_ports' => 'array',
            'tor_exit' => 'boolean',
            'checked_at' => 'datetime',
        ];
    }
}
