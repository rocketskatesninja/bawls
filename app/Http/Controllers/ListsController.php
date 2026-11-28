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
 * The blocklist: every outside address that raised an alert, each with its
 * fail2ban ban when it has one, so who is banned right now is a filter on the
 * same table rather than a list of its own.
 */
class ListsController extends Controller
{
    public function index(Settings $settings): Response
    {
        $export = Bans::current();
        $entries = Blocklist::entries();

        // A ban no listed address accounts for (its alert has aged out, or
        // was never raised) still gets a row, so nothing banned is invisible.
        $banOf = $entries->mapWithKeys(fn (array $entry): array => [$entry['ip'] => Bans::find($entry['ip'])]);
        $covered = $banOf->filter()->pluck('ip')->flip();
        $orphans = collect($export['bans'])->reject(fn (array $ban): bool => isset($covered[$ban['ip']]));

        $ips = $entries->pluck('ip');
        $intel = IpIntel::query()
            ->whereIn('ip', $ips->merge($orphans->pluck('ip'))->unique())
            ->get(['ip', 'country', 'as_org'])
            ->keyBy('ip');
        // Addresses whose alerts were hidden or dismissed, which a row can reopen.
        $reopenable = Alert::reopenable($ips);

        $ban = fn (?array $ban, string $ip): ?array => $ban ? [
            'block' => $ban['ip'] !== $ip ? $ban['ip'] : null,   // banned as part of this IPv6 block
            'banned_at' => $settings->stamp($ban['banned_at'], seconds: false),
            'expires_at' => $settings->stamp($ban['expires_at'], seconds: false),
            'expires_ts' => $ban['expires_at']->getTimestamp(),   // for sorting
            'expires_in' => $ban['expires_at']->diffForHumans(['parts' => 2, 'short' => true]),
        ] : null;

        $rows = $entries->map(fn (array $entry): array => [
            'ip' => $entry['ip'],
            'dossier' => true,
            'country' => $intel[$entry['ip']]->country ?? null,
            'org' => $intel[$entry['ip']]->as_org ?? null,
            'rules' => $entry['rules'],
            'alerts' => $entry['alerts'],
            'severity' => $entry['severity'],
            'last_seen' => $settings->stamp($entry['last_seen_at'], seconds: false),
            'last_seen_ts' => $entry['last_seen_at']->getTimestamp(),   // for sorting
            'ban' => $ban($banOf[$entry['ip']], $entry['ip']),
            'reopen' => isset($reopenable[$entry['ip']]),
        ])->concat($orphans->map(fn (array $orphan): array => [
            'ip' => $orphan['ip'],
            'dossier' => ! str_contains($orphan['ip'], '/'),   // a bare block has no dossier
            'country' => $intel[$orphan['ip']]->country ?? null,
            'org' => $intel[$orphan['ip']]->as_org ?? null,
            'rules' => [],
            'alerts' => 0,
            'severity' => null,
            'last_seen' => null,
            'last_seen_ts' => 0,
            'ban' => $ban($orphan, $orphan['ip']),
            'reopen' => false,
        ]));

        return Inertia::render('Lists', [
            'bans' => [
                'enabled' => (bool) config('bawls.ban.enabled'),
                'as_of' => $export['as_of'] ? $settings->stamp($export['as_of']) : null,
                'stale' => $export['as_of']?->lt(now()->subMinutes(Bans::STALE_AFTER_MINUTES)) ?? false,
            ],
            'rows' => $rows->values()->all(),
        ]);
    }
}
