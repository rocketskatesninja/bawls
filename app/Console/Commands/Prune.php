<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class Prune extends Command
{
    protected $signature = 'bawls:prune';

    protected $description = 'Expire noise quickly but keep attacker evidence and alerts';

    public function handle(): int
    {
        $benignCutoff = now()->subDays((int) config('bawls.retention.benign_days'));
        $attackerCutoff = now()->subDays((int) config('bawls.retention.attacker_days'));
        $alertCutoff = now()->subDays((int) config('bawls.retention.alerts_days'));

        // Noise: events past the short window that neither tripped a non-harmless
        // signature nor came from an IP that raised an alert.
        $noise = Event::where('occurred_at', '<', $benignCutoff)
            ->where(fn ($q) => $q->whereNull('raw->signature')->orWhereIn('raw->signature', Event::HARMLESS_SIGNATURES))
            ->whereNotExists(fn ($q) => $q->select(DB::raw(1))->from('alerts')
                ->whereColumn('alerts.src_ip', 'events.src_ip'))
            ->delete();

        // Evidence (flagged signatures, alerted IPs) expires only at the long
        // window, so you can still look back weeks later.
        $aged = Event::where('occurred_at', '<', $attackerCutoff)->delete();

        // Open alerts are never pruned: an unreviewed detection must not vanish
        // just because it aged out.
        $alerts = Alert::where('last_seen_at', '<', $alertCutoff)
            ->where('status', '!=', 'open')
            ->delete();

        // IP intel outlives nothing: once an IP has no events left (its records
        // aged out above), its dossier is orphaned, so drop it. It re-enriches
        // automatically if the IP comes back. This caps the only table that
        // would otherwise grow unbounded with distinct scanner IPs.
        $intel = IpIntel::whereNotExists(fn ($q) => $q->select(DB::raw(1))->from('events')
            ->whereColumn('events.src_ip', 'ip_intel.ip'))->delete();

        $this->info("Pruned {$noise} noise + {$aged} aged event(s), {$alerts} alert(s), {$intel} dossier(s).");

        return self::SUCCESS;
    }
}
