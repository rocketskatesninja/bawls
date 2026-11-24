<?php

use App\Http\Controllers\Api\IngestController;
use App\Http\Middleware\AuthenticateSensor;
use Illuminate\Support\Facades\Route;

// Sensor ingest. Throttled generously because a batch carries up to 500
// events: the cap is there to stop a runaway agent, not to shape traffic.
// The limit is per sensor ("ingest", AppServiceProvider): they all connect
// from 127.0.0.1, so a shared bucket would let one sensor starve the others.
Route::middleware([AuthenticateSensor::class, 'throttle:ingest'])
    ->post('/ingest', [IngestController::class, 'store'])
    ->name('api.ingest');
