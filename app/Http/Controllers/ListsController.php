<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\IpIntel;
use App\Services\Bans;
use App\Services\Blocklist;
use App\Services\Settings;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The two lists of attacker addresses: who fail2ban is banning right now,
 * and the blocklist feed (every external address that raised an alert).
 */
class ListsController extends Controller
{
    public function index(Settings $settings): Response
    {
        $export = Bans::current();
        $bans = collect($export['bans']);
        $blocklist = Blocklist::entries();

        $intel = IpIntel::query()
            ->whereIn('ip', $bans->pluck('ip')->merge($blocklist->pluck('ip'))->unique())
            ->get(['ip', 'country', 'as_org'])
            ->keyBy('ip');

        // Why each address is banned: its worst alert, which for a ban is the
        // exploit attempt that triggered it.
        $alerts = Alert::query()
            ->whereIn('src_ip', $bans->pluck('ip'))
            ->orderByDesc('severity')
            ->orderByDesc('last_seen_at')
            ->get(['src_ip', 'rule', 'severity', 'title'])
            ->unique('src_ip')
            ->keyBy('src_ip');

        $banned = $bans->pluck('ip')->flip();
        $format = 'M j H:i';

        return Inertia::render('Lists', [
            'bans' => [
                'enabled' => (bool) config('bawls.ban.enabled'),
                'as_of' => $export['as_of'] ? $settings->local($export['as_of'])->format('M j H:i:s') : null,
                'stale' => $export['as_of']?->lt(now()->subMinutes(Bans::STALE_AFTER_MINUTES)) ?? false,
                'rows' => $bans->map(fn (array $ban): array => [
                    'ip' => $ban['ip'],
                    'country' => $intel[$ban['ip']]->country ?? null,
                    'org' => $intel[$ban['ip']]->as_org ?? null,
                    'rule' => $alerts[$ban['ip']]->rule ?? null,
                    'severity' => $alerts[$ban['ip']]->severity ?? null,
                    'title' => $alerts[$ban['ip']]->title ?? null,
                    'banned_at' => $settings->local($ban['banned_at'])->format($format),
                    'expires_at' => $settings->local($ban['expires_at'])->format($format),
                    'expires_in' => $ban['expires_at']->diffForHumans(['parts' => 2, 'short' => true]),
                ])->values()->all(),
            ],
            'blocklist' => $blocklist->map(fn (array $entry): array => [
                'ip' => $entry['ip'],
                'country' => $intel[$entry['ip']]->country ?? null,
                'org' => $intel[$entry['ip']]->as_org ?? null,
                'rules' => $entry['rules'],
                'alerts' => $entry['alerts'],
                'severity' => $entry['severity'],
                'last_seen' => $settings->local($entry['last_seen_at'])->format($format),
                'banned' => $banned->has($entry['ip']),
            ])->all(),
        ]);
    }
}
