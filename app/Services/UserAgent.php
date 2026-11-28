<?php

namespace App\Services;

/**
 * A deliberately small User-Agent summariser.
 *
 * It reads only what the client already sent in its header — no probing, no
 * JavaScript — and reduces it to a short label plus whether it looks automated.
 * It is heuristic, not exhaustive: enough to tell a real browser from a
 * scanner at a glance on the dossier.
 */
class UserAgent
{
    /** @var array<int, string> Substrings that mark a client as automated. */
    private const TOOLS = [
        'nikto', 'sqlmap', 'nmap', 'masscan', 'zgrab', 'zmap', 'nuclei', 'gobuster',
        'dirbuster', 'feroxbuster', 'wpscan', 'curl', 'wget', 'python-requests',
        'python-urllib', 'go-http-client', 'libwww', 'httpx', 'censys', 'shodan',
        'semrush', 'ahrefs', 'bitdiscovery', 'l9explore',
        // The sensors' scanner list ends here (SCANNER_UA_RE in
        // sensors/signatures.py; SignatureParityTest keeps this a superset).
        // These are automated too, though not scanners:
        'bot', 'spider', 'crawler',
    ];

    /**
     * @return array{label: string, browser: ?string, os: ?string, bot: bool}
     */
    public static function summarize(?string $ua): array
    {
        $ua = trim((string) $ua);

        if ($ua === '') {
            return ['label' => 'no user-agent', 'browser' => null, 'os' => null, 'bot' => true];
        }

        foreach (self::TOOLS as $tool) {
            if (stripos($ua, $tool) !== false) {
                return ['label' => $tool, 'browser' => null, 'os' => null, 'bot' => true];
            }
        }

        $browser = self::match($ua, [
            'Edg' => 'Edge', 'OPR' => 'Opera', 'Chrome' => 'Chrome',
            'Firefox' => 'Firefox', 'Safari' => 'Safari',
        ]);
        $os = self::match($ua, [
            'Windows' => 'Windows', 'Android' => 'Android', 'iPhone' => 'iOS',
            'iPad' => 'iPadOS', 'Mac OS X' => 'macOS', 'CrOS' => 'ChromeOS', 'Linux' => 'Linux',
        ]);

        $label = $browser && $os ? "{$browser} on {$os}" : ($browser ?? $os ?? 'unknown client');

        return ['label' => $label, 'browser' => $browser, 'os' => $os, 'bot' => false];
    }

    /**
     * @param  array<string, string>  $map  needle => label, checked in order
     */
    private static function match(string $ua, array $map): ?string
    {
        foreach ($map as $needle => $label) {
            if (str_contains($ua, $needle)) {
                return $label;
            }
        }

        return null;
    }
}
