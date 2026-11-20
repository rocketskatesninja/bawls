<?php

namespace App\Http\Controllers;

use App\Services\Settings;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class SettingsController extends Controller
{
    public function edit(Settings $settings): Response
    {
        return Inertia::render('Settings', [
            'values' => $settings->all(),
            'defaults' => Settings::DEFAULTS,
            'zones' => Settings::zoneChoices(),
            'minContrast' => Settings::MIN_CONTRAST,
        ]);
    }

    public function update(Request $request, Settings $settings): RedirectResponse
    {
        $values = $request->validate([
            'timezone' => ['required', 'string', 'timezone:all'],
            'accent' => ['required', 'string', 'regex:/^#[0-9a-fA-F]{6}$/', function (string $attribute, mixed $value, Closure $fail): void {
                if (preg_match('/^#[0-9a-fA-F]{6}$/', $value) && Settings::contrast($value) < Settings::MIN_CONTRAST) {
                    $fail('That colour is too dark to read on the console\'s black background.');
                }
            }],
        ], [
            'accent.regex' => 'Use a colour like #39ff8b.',
            'timezone.timezone' => 'Pick a time zone from the list.',
        ]);

        $settings->update([
            'timezone' => $values['timezone'],
            'accent' => strtolower($values['accent']),
        ]);

        return back();
    }
}
