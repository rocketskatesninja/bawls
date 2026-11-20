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

    protected $fillable = ['name', 'host', 'kind', 'token_hash', 'enabled'];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return [
            'last_seen_at' => 'datetime',
            'enabled' => 'boolean',
        ];
    }

    public function events(): HasMany
    {
        return $this->hasMany(Event::class);
    }
}
