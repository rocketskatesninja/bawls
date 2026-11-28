<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

/**
 * A strict Content-Security-Policy for the console.
 *
 * The console renders text attackers control (paths, user agents, form
 * fields). Vue escapes all of it today; this is the second layer, so a future
 * slip (a v-html, an innerHTML) still can't run a script or exfiltrate data.
 * Everything is same-origin: the app bundle, the MapLibre worker and the
 * bundled basemap all come from this host.
 */
class ContentSecurityPolicy
{
    private const POLICY = [
        "default-src 'self'",
        "script-src 'self'",
        "worker-src 'self'",
        // Vue :style bindings and MapLibre set element styles at runtime.
        "style-src 'self' 'unsafe-inline'",
        // The inline SVG favicon is a data: URI.
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        // The Vite dev server serves assets from another origin with HMR.
        if (! Vite::isRunningHot()) {
            $response->headers->set('Content-Security-Policy', implode('; ', self::POLICY));
        }

        return $response;
    }
}
