<?php

namespace App\Console\Commands;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Services\IpEnricher;
use App\Services\Network;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;

class Enrich extends Command
{
    protected $signature = 'bawls:enrich
                            {--ip= : Enrich one IP now, ignoring the candidate filter and its freshness}';

    protected $description = 'Build passive OSINT dossiers for suspicious attacker IPs';

    public function handle(IpEnricher $enricher): int
    {
        if ($single = $this->option('ip')) {
            $intel = $enricher->enrich($single);
            if (! $intel) {
                $this->error("Not a valid IP: {$single}");

                return self::FAILURE;
            }
            $this->info("Enriched {$single}: {$intel->country} / {$intel->city} · AS{$intel->asn} {$intel->as_org}");

            return self::SUCCESS;
        }

        $candidates = $this->candidates();

        foreach ($candidates as $ip) {
            $enricher->enrich($ip);
        }

        $this->info($candidates->isEmpty()
            ? 'No IPs due for enrichment.'
            : "Enriched {$candidates->count()} IP(s).");

        return self::SUCCESS;
    }

    /**
     * Suspicious external IPs seen recently whose dossier is missing or stale,
     * capped per run.
     *
     * @return Collection<int, string>
     */
    private function candidates(): Collection
    {
        $lookback = now()->subDays((int) config('bawls.enrich.lookback_days'));

        // A non-harmless HTTP hit (decoy or real site) or a firewall block marks an IP as suspicious.
        $suspicious = Event::query()
            ->where('occurred_at', '>=', $lookback)
            ->where(function ($query): void {
                $query
                    ->where(fn ($q) => $q->whereIn('source', Event::HTTP_SOURCES)->whereNotIn('raw->signature', Event::HARMLESS_SIGNATURES))
                    ->orWhere('action', 'blocked');
            })
            ->distinct()
            ->pluck('src_ip');

        $alertIps = Alert::query()
            ->where('last_seen_at', '>=', $lookback)
            ->whereNotNull('src_ip')
            ->distinct()
            ->pluck('src_ip');

        $candidates = $suspicious->merge($alertIps);

        if (config('bawls.enrich.benign')) {
            $candidates = $candidates->merge(
                Event::where('occurred_at', '>=', $lookback)->distinct()->pluck('src_ip')
            );
        }

        $fresh = IpIntel::query()
            ->where('checked_at', '>=', now()->subDays((int) config('bawls.enrich.recheck_days')))
            ->pluck('ip')
            ->flip();

        return $candidates
            ->unique()
            ->reject(fn ($ip): bool => ! filter_var($ip, FILTER_VALIDATE_IP) || Network::isInternal($ip))
            ->reject(fn ($ip): bool => isset($fresh[$ip]))
            ->take((int) config('bawls.enrich.per_run'))
            ->values();
    }
}
