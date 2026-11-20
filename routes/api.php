<?php

use App\Http\Controllers\Api\IngestController;
use App\Http\Middleware\AuthenticateSensor;
use Illuminate\Support\Facades\Route;

// Sensor ingest. Throttled generously because a batch carries up to 500
// events — the cap is there to stop a runaway agent, not to shape traffic.
Route::middleware([AuthenticateSensor::class, 'throttle:120,1'])
    ->post('/ingest', [IngestController::class, 'store'])
    ->name('api.ingest');
