<?php

namespace App\Services;

use App\Models\Event;
use Closure;
use Illuminate\Support\Facades\Cache;

/**
 * Search-engine crawlers are never banned. An exploit string can reach the
 * real Googlebot through a planted link (on the decoy or a real site), and a
 * week-long ban on every port would cost those sites their search ranking.
 *
 * A user agent alone proves nothing (attackers wear Googlebot's all the
 * time), so a claim is checked the way the engines document it: the address's
 * reverse DNS must be in the engine's domain, and that name must resolve back
 * to the address. The verdict is cached for a day.
 */
class Crawler
{
    /** User-agent token => the domains its genuine crawlers' reverse DNS ends in. */
    private const ENGINES = [
        // Not googleusercontent.com: every Google Cloud VM resolves to that.
        'googlebot' => ['googlebot.com', 'google.com'],
        'bingbot' => ['search.msn.com'],
        'applebot' => ['applebot.apple.com'],
        'yandex' => ['yandex.ru', 'yandex.net', 'yandex.com'],
        'baiduspider' => ['baidu.com', 'baidu.jp'],
    ];

    /**
     * Replaces the DNS lookups in tests: fn (string $ip): array{0: ?string, 1: list<string>}
     * returning the address's reverse name and that name's forward addresses.
     */
    public static ?Closure $dns = null;

    /** True when the address claims a search engine in its recent requests and DNS confirms it. */
    public static function verified(string $ip): bool
    {
        $engine = self::claimed($ip);
        if ($engine === null) {
            return false;
        }

        return Cache::remember("bawls:crawler:{$engine}:{$ip}", now()->addDay(),
            fn (): bool => self::confirms($ip, self::ENGINES[$engine]));
    }

    /** The engine the address's latest HTTP requests claim to be, if any. */
    private static function claimed(string $ip): ?string
    {
        $agents = Event::query()
            ->where('src_ip', $ip)
            ->whereIn('source', Event::HTTP_SOURCES)
            ->latest('occurred_at')
            ->limit(20)
            ->pluck('raw')
            ->map(fn (?array $raw): string => strtolower((string) ($raw['user_agent'] ?? '')));

        foreach (array_keys(self::ENGINES) as $engine) {
            if ($agents->contains(fn (string $agent): bool => str_contains($agent, $engine))) {
                return $engine;
            }
        }

        return null;
    }

    /** @param list<string> $domains */
    private static function confirms(string $ip, array $domains): bool
    {
        [$name, $forward] = (self::$dns ?? self::lookup(...))($ip);
        if ($name === null) {
            return false;
        }
        $name = strtolower(rtrim($name, '.'));
        $inDomain = array_filter($domains, fn (string $domain): bool => str_ends_with($name, ".{$domain}"));

        return $inDomain !== [] && in_array(self::canonical($ip), array_map(self::canonical(...), $forward), true);
    }

    /** One spelling per address (IPv6 has many). */
    private static function canonical(string $address): string
    {
        $packed = @inet_pton($address);

        return $packed === false ? $address : (string) inet_ntop($packed);
    }

    /** @return array{0: ?string, 1: list<string>} */
    private static function lookup(string $ip): array
    {
        $name = @gethostbyaddr($ip);
        if (! is_string($name) || $name === $ip) {
            return [null, []];
        }
        $forward = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            ? array_column(@dns_get_record($name, DNS_AAAA) ?: [], 'ipv6')
            : (@gethostbynamel($name) ?: []);

        return [$name, array_values($forward)];
    }
}
