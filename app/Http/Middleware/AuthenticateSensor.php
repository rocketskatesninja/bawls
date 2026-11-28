<?php

namespace App\Http\Middleware;

use App\Models\Sensor;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateSensor
{
    /**
     * Resolve the sensor from its bearer token and stash it on the request.
     *
     * Sensor tokens are machine credentials sent on every batch, so they are
     * stored as a plain SHA-256 digest rather than bcrypt: we need a lookup
     * that is cheap enough to run at ingest rate, and the token is 48 random
     * characters (bawls:sensor) so it has nothing to brute force.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->bearerToken() ?? $request->header('X-Sensor-Token');

        if (! is_string($token) || $token === '') {
            return response()->json(['message' => 'Sensor token missing.'], 401);
        }

        $sensor = Sensor::where('token_hash', hash('sha256', $token))->first();

        if (! $sensor || ! $sensor->enabled) {
            return response()->json(['message' => 'Sensor token invalid.'], 401);
        }

        $request->attributes->set('sensor', $sensor);

        return $next($request);
    }
}
