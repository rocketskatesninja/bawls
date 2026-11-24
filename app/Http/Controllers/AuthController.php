<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Session auth for the console.
 *
 * There is deliberately no registration route: Bawls is a private
 * monitoring console, and accounts are created from the CLI with
 * `php artisan bawls:user`. An open sign-up here would hand anyone
 * who can reach the port a view of the network's traffic.
 */
class AuthController extends Controller
{
    /** Login attempts allowed per throttle key before lockout. */
    private const MAX_ATTEMPTS = 5;

    private const DECAY_SECONDS = 60;

    public function show(): Response
    {
        // The form posts back to the same secret slug; the page never hardcodes
        // /login, which does not exist here.
        return Inertia::render('Login', [
            'loginUrl' => route('login'),
        ]);
    }

    public function login(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $key = $this->throttleKey($request);

        if (RateLimiter::tooManyAttempts($key, self::MAX_ATTEMPTS)) {
            throw ValidationException::withMessages([
                'email' => 'Too many attempts. Try again in '.RateLimiter::availableIn($key).' seconds.',
            ]);
        }

        if (! Auth::attempt($credentials, $request->boolean('remember'))) {
            RateLimiter::hit($key, self::DECAY_SECONDS);

            // Deliberately vague: distinguishing "no such user" from "wrong
            // password" tells an attacker which accounts exist.
            throw ValidationException::withMessages([
                'email' => 'Those credentials do not match our records.',
            ]);
        }

        RateLimiter::clear($key);
        $request->session()->regenerate();

        // Straight to the overview, not intended(): a guest never reaches a
        // console URL to be remembered (those 404), so there is nothing to
        // return to.
        return redirect()->route('overview');
    }

    public function logout(Request $request): RedirectResponse
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    /** Throttle on email *and* IP so one attacker cannot lock out a real user. */
    private function throttleKey(Request $request): string
    {
        return 'login:'.mb_strtolower((string) $request->input('email')).'|'.$request->ip();
    }
}
