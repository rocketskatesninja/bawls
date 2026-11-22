<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * One console preference. Read and written through App\Services\Settings,
 * which owns the defaults and the validation.
 */
class Setting extends Model
{
    protected $primaryKey = 'key';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['key', 'value'];
}
