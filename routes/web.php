<?php

use App\Http\Controllers\AlertController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\BlocklistController;
use App\Http\Controllers\CredentialsController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\EventController;
use App\Http\Controllers\IpController;
use App\Http\Controllers\ListsController;
use App\Http\Controllers\SettingsController;
use App\Http\Controllers\StreamController;
use Illuminate\Support\Facades\Route;

// The console sign-in lives at a secret slug (config/bawls.php -> login_path),
// never at /login, so a scan for an admin login turns up nothing. Registering
// the web routes without a real slug is refused rather than quietly exposing
// one at a guessable path.
$loginPath = trim((string) config('bawls.login_path'), '/');

if ($loginPath === '' || $loginPath === 'login') {
    throw new RuntimeException('BAWLS_LOGIN_PATH must be set to a secret slug (and cannot be "login").');
}

Route::middleware('guest')->group(function () use ($loginPath): void {
    Route::get($loginPath, [AuthController::class, 'show'])->name('login');
    Route::post($loginPath, [AuthController::class, 'login']);
});

Route::middleware('auth')->group(function (): void {
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    Route::get('/', [DashboardController::class, 'overview'])->name('overview');
    Route::get('/stream/check', [StreamController::class, 'check'])->name('stream.check');
    Route::get('/stream/export', [StreamController::class, 'export'])->name('stream.export');
    Route::get('/events/{event}', [EventController::class, 'show'])->name('events.show')->whereNumber('event');
    Route::get('/ip', [IpController::class, 'index'])->name('ip.index');
    Route::get('/ip/{ip}', [IpController::class, 'show'])->name('ip.show')
        ->where('ip', '[0-9A-Fa-f:.]+');
    Route::get('/credentials', [CredentialsController::class, 'index'])->name('credentials');
    Route::get('/lists', [ListsController::class, 'index'])->name('lists');
    Route::get('/blocklist.txt', [BlocklistController::class, 'show'])->name('blocklist');
    Route::post('/alerts/{alert}/ack', [AlertController::class, 'acknowledge'])->name('alerts.ack');
    Route::post('/alerts/{alert}/resolve', [AlertController::class, 'resolve'])->name('alerts.resolve');
    Route::get('/settings', [SettingsController::class, 'edit'])->name('settings');
    Route::put('/settings', [SettingsController::class, 'update'])->name('settings.update');
});
