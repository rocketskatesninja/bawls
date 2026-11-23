<?php

namespace App\Services;

use App\Models\Alert;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;

/**
 * The actionable payoff of the honeypot: external IPs that raised an alert,
 * ready to feed a firewall. Private and never-block addresses are never
 * listed, and never banned.
 */
class Blocklist
{
    /**
     * @return Collection<int, string>
     */
    public static function ips(int $days = 30): Collection
    {
        return self::entries($days)->pluck('ip');
    }

    /**
     * The blocklist with what put each address on it, worst first: its alert
     * rules, how many alerts, the highest severity and when it was last seen.
     *
     * @return Collection<int, array{ip: string, rules: list<string>, alerts: int, severity: int, last_seen_at: Carbon}>
     */
    public static function entries(int $days = 30): Collection
    {
        return Alert::query()
            ->whereNotNull('src_ip')
            ->where('last_seen_at', '>=', now()->subDays($days))
            ->get(['src_ip', 'rule', 'severity', 'last_seen_at'])
            ->groupBy('src_ip')
            ->filter(fn (Collection $alerts, string $ip): bool => self::eligible($ip))
            ->map(fn (Collection $alerts, string $ip): array => [
                'ip' => $ip,
                'rules' => $alerts->pluck('rule')->unique()->sort()->values()->all(),
                'alerts' => $alerts->count(),
                'severity' => (int) $alerts->max('severity'),
                'last_seen_at' => $alerts->max('last_seen_at'),
            ])
            ->sortBy([['severity', 'desc'], ['last_seen_at', 'desc']])
            ->values();
    }

    /** True when an address may be listed or banned: external and not on the never-block list. */
    public static function eligible(string $ip): bool
    {
        return ! Network::isInternal($ip)
            && ! Network::inAny($ip, self::list('bawls.ban.never_block'));
    }

    /**
     * Ask the firewall to ban an alert's source by appending a line to the
     * ban log, which a fail2ban jail watches. No-op unless the feed is
     * enabled, the alert's rule is a banning rule, and the IP is eligible.
     */
    public static function ban(Alert $alert): void
    {
        if (! config('bawls.ban.enabled')
            || ! $alert->src_ip
            || ! in_array($alert->rule, self::list('bawls.ban.rules'), true)
            || ! self::eligible($alert->src_ip)) {
            return;
        }
        // A genuine search-engine crawler is recorded and alerted, never banned.
        if (Crawler::verified($alert->src_ip)) {
            return;
        }

        // Stamped with the write time, not the attack time, so it always
        // falls inside fail2ban's findtime.
        $line = now()->utc()->format('Y-m-d\TH:i:s\Z')
            ." bawls ban {$alert->src_ip} rule={$alert->rule} alert={$alert->id}\n";

        file_put_contents(config('bawls.ban.log'), $line, FILE_APPEND | LOCK_EX);
    }

    public static function text(int $days = 30): string
    {
        $ips = self::ips($days);

        return '# bawls blocklist · generated '.now()->toIso8601String()." · {$ips->count()} IP(s)\n"
            .$ips->implode("\n")."\n";
    }

    /**
     * A comma-separated config value as a clean list (spaces and empty
     * entries dropped). Accepts an array too, for tests and overrides.
     *
     * @return array<int, string>
     */
    private static function list(string $key): array
    {
        $value = config($key, '');
        $items = is_array($value) ? $value : explode(',', (string) $value);

        return array_values(array_filter(array_map('trim', $items), fn (string $item): bool => $item !== ''));
    }
}
