<?php

namespace App\Providers;

use App\Services\Settings;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Console preferences are read once per request, then reused.
        $this->app->scoped(Settings::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Each sensor gets its own ingest budget (routes/api.php).
        RateLimiter::for('ingest', fn (Request $request): Limit => Limit::perMinute(120)
            ->by('sensor:'.($request->attributes->get('sensor')?->id ?? $request->ip())));
    }
}
