<?php

namespace App\Services;

use Carbon\CarbonImmutable;

/**
 * fail2ban's current bans in the bawls jail. Only root can ask fail2ban, so
 * this reads the copy the installer's bawls-bans timer writes every minute:
 * a "# utc-offset +0000" line, then `fail2ban-client get bawls banip
 * --with-time` lines such as
 *   203.0.113.9 	2026-11-18 05:54:00 + 604800 = 2026-11-25 05:54:00
 * with the times in the server's local zone.
 */
class Bans
{
    /** A copy older than this means the timer has stopped refreshing it. */
    public const STALE_AFTER_MINUTES = 5;

    private const BAN_LINE = '/^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ \d+ = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$/';

    /**
     * The bans, newest first, and when the copy was written (null when there
     * is no copy to read).
     *
     * @return array{as_of: CarbonImmutable|null, bans: list<array{ip: string, banned_at: CarbonImmutable, expires_at: CarbonImmutable}>}
     */
    public static function current(): array
    {
        $path = (string) config('bawls.ban.export');
        if (! is_file($path) || ! is_readable($path)) {
            return ['as_of' => null, 'bans' => []];
        }

        $offset = '+0000';
        $bans = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            $line = trim($line);
            if (preg_match('/^# utc-offset ([+-]\d{4})$/', $line, $match)) {
                $offset = $match[1];

                continue;
            }
            if (! preg_match(self::BAN_LINE, $line, $match) || filter_var($match[1], FILTER_VALIDATE_IP) === false) {
                continue;
            }
            $bans[] = [
                'ip' => $match[1],
                'banned_at' => self::time($match[2], $offset),
                'expires_at' => self::time($match[3], $offset),
            ];
        }
        usort($bans, fn (array $a, array $b): int => $b['banned_at'] <=> $a['banned_at']);

        return ['as_of' => CarbonImmutable::createFromTimestampUTC((int) filemtime($path)), 'bans' => $bans];
    }

    private static function time(string $local, string $offset): CarbonImmutable
    {
        return CarbonImmutable::createFromFormat('Y-m-d H:i:s', $local, $offset)->utc();
    }
}
