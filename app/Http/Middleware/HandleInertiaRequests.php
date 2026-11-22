<?php

namespace App\Http\Middleware;

use App\Services\Settings;
use Illuminate\Http\Request;
use Inertia\Middleware;

class HandleInertiaRequests extends Middleware
{
    /**
     * The root template that's loaded on the first page visit.
     *
     * @see https://inertiajs.com/server-side-setup#root-template
     *
     * @var string
     */
    protected $rootView = 'app';

    public function __construct(private Settings $settings) {}

    /**
     * Define the props that are shared by default.
     *
     * @see https://inertiajs.com/shared-data
     *
     * @return array<string, mixed>
     */
    public function share(Request $request): array
    {
        return [
            ...parent::share($request),
            'auth' => [
                'user' => $request->user()?->only('name', 'email'),
            ],
            // Every page needs these: times are shown in the chosen zone, and
            // the accent colour is applied without a full reload.
            'settings' => fn (): array => [
                'timezone' => $this->settings->timezone(),
                'timezone_label' => $this->settings->timezoneLabel(),
                'accent' => $this->settings->accent(),
                'accent_dim' => $this->settings->accentDim(),
                'text_size' => $this->settings->textSize(),
            ],
        ];
    }
}
