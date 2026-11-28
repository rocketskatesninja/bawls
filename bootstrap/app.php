<?php

use App\Http\Middleware\AuthenticateSensor;
use App\Http\Middleware\ContentSecurityPolicy;
use App\Http\Middleware\HandleInertiaRequests;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->web(append: [
            HandleInertiaRequests::class,
            ContentSecurityPolicy::class,
        ]);
        // The ingest rate limit is per sensor, so the sensor must be known
        // before the throttle runs (Laravel would otherwise sort throttling first).
        $middleware->prependToPriorityList(before: ThrottleRequests::class, prepend: AuthenticateSensor::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        // A signed-out visitor to a console route gets a flat 404, whatever
        // they ask for and however: never a redirect to the login, a JSON 401,
        // a 419 for a missing CSRF token or a 405 for the wrong verb. Nothing
        // on this host should hint that a console, or a login for it, exists
        // here. Only the sensors' API keeps its JSON errors, and the sign-in
        // form itself its 419 (a page left open until the session expired).
        $hidden = fn (Request $request): bool => ! $request->is('api/*')
            && ! $request->is(trim((string) config('bawls.login_path'), '/'))
            && $request->user() === null;

        $exceptions->render(function (AuthenticationException $e, Request $request) {
            if (! $request->is('api/*')) {
                abort(404);
            }
        });
        $exceptions->render(function (HttpExceptionInterface $e, Request $request) use ($hidden) {
            if (in_array($e->getStatusCode(), [405, 419], true) && $hidden($request)) {
                abort(404);
            }
        });
    })->create();
