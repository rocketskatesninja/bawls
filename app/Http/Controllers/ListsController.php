<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use App\Models\IpIntel;
use App\Services\Bans;
use App\Services\Blocklist;
use App\Services\Network;
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

        // A banned IPv6 block is listed as the block; its details (country,
        // the alert behind it, its dossier) are those of the address in it
        // that raised the alert.
        $offenders = Alert::query()
            ->where('src_ip', 'like', '%:%')
            ->orderByDesc('last_seen_at')
            ->pluck('src_ip')
            ->unique();
        $bans = $bans->map(fn (array $ban): array => $ban + [
            'address' => str_contains($ban['ip'], '/')
                ? $offenders->first(fn (string $ip): bool => Network::inCidr($ip, $ban['ip']))
                : $ban['ip'],
        ]);

        $intel = IpIntel::query()
            ->whereIn('ip', $bans->pluck('address')->filter()->merge($blocklist->pluck('ip'))->unique())
            ->get(['ip', 'country', 'as_org'])
            ->keyBy('ip');

        // Why each address is banned: its worst alert, which for a ban is the
        // exploit attempt that triggered it.
        $alerts = Alert::query()
            ->whereIn('src_ip', $bans->pluck('address')->filter())
            ->orderByDesc('severity')
            ->orderByDesc('last_seen_at')
            ->get(['src_ip', 'rule', 'severity', 'title'])
            ->unique('src_ip')
            ->keyBy('src_ip');

        return Inertia::render('Lists', [
            'bans' => [
                'enabled' => (bool) config('bawls.ban.enabled'),
                'as_of' => $export['as_of'] ? $settings->stamp($export['as_of']) : null,
                'stale' => $export['as_of']?->lt(now()->subMinutes(Bans::STALE_AFTER_MINUTES)) ?? false,
                'rows' => $bans->map(fn (array $ban): array => [
                    'ip' => $ban['ip'],
                    'address' => $ban['address'],   // for the dossier link; null when no alert names one
                    'country' => $intel[$ban['address']]->country ?? null,
                    'org' => $intel[$ban['address']]->as_org ?? null,
                    'rule' => $alerts[$ban['address']]->rule ?? null,
                    'severity' => $alerts[$ban['address']]->severity ?? null,
                    'title' => $alerts[$ban['address']]->title ?? null,
                    'banned_at' => $settings->stamp($ban['banned_at'], seconds: false),
                    'banned_ts' => $ban['banned_at']->getTimestamp(),   // for sorting
                    'expires_at' => $settings->stamp($ban['expires_at'], seconds: false),
                    'expires_ts' => $ban['expires_at']->getTimestamp(),
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
                'last_seen' => $settings->stamp($entry['last_seen_at'], seconds: false),
                'last_seen_ts' => $entry['last_seen_at']->getTimestamp(),   // for sorting
                'banned' => Bans::find($entry['ip']) !== null,
            ])->all(),
        ]);
    }
}
