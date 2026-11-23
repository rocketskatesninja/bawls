<?php

namespace App\Services;

use App\Models\Event;

/**
 * Plain-English meanings for what the console shows: the signatures a
 * request is labelled with, the stream's kinds and the alert rules, each
 * saying whether it bans. Whether something bans is read from config, never
 * written into the text, so the words can't drift from what bawls does.
 */
class Glossary
{
    private const SIGNATURES = [
        'cve_probe' => 'Tried a known exploit for a specific product (a published CVE).',
        'rce' => 'Tried to run commands on the server.',
        'sqli' => 'Tried SQL injection, to read or change a database.',
        'traversal' => 'Tried to climb out of the web folder to read system files.',
        'login' => 'Sent a username and password to a sign-in form.',
        'dirbust' => 'Hunted for files that should never be public: backups, .env and keys, admin panels.',
        'scanner_ua' => 'Came from a known scanning tool, going by its user agent.',
        'flood' => 'More requests in a minute than the decoy records one by one: the rest are counted here.',
        'benign' => 'Nothing suspicious: an ordinary page view.',
        'browser_check' => 'Ran the opt-in browser self-test.',
    ];

    private const KINDS = [
        'exploit' => 'An attack payload: a product exploit, command or SQL injection, or path traversal.',
        'login' => 'A password guess at a sign-in form.',
        'scan' => 'Looking around: file hunting, a scanning tool, or a flood.',
        'page' => 'An ordinary page view.',
        'firewall' => 'A connection the firewall blocked.',
        'other' => 'Host traffic the firewall let through.',
    ];

    /**
     * @return array{signatures: array<string, array{text: string, bans: bool}>, kinds: array<string, array{text: string, bans: bool}>, rules: array<string, array{text: string, bans: bool}>}
     */
    public function all(): array
    {
        // Exploit signatures ban through the web_exploit rule.
        $exploitBans = $this->ruleBans('web_exploit');
        $exploitSignatures = (array) config('bawls.rules.web_exploit.signatures', Event::EXPLOIT_SIGNATURES);

        $signatures = [];
        foreach (self::SIGNATURES as $signature => $text) {
            $signatures[$signature] = ['text' => $text, 'bans' => $exploitBans && in_array($signature, $exploitSignatures, true)];
        }
        $kinds = [];
        foreach (self::KINDS as $kind => $text) {
            $kinds[$kind] = ['text' => $text, 'bans' => $kind === 'exploit' && $exploitBans];
        }
        $rules = [];
        foreach ((array) config('bawls.rules') as $name => $rule) {
            $rules[$name] = ['text' => $this->rule($name, (array) $rule), 'bans' => $this->ruleBans($name)];
        }

        return ['signatures' => $signatures, 'kinds' => $kinds, 'rules' => $rules];
    }

    /** Does an alert from this rule ban its address (bawls.ban.rules, with banning on)? */
    private function ruleBans(string $rule): bool
    {
        $rules = array_map('trim', explode(',', (string) config('bawls.ban.rules')));

        return (bool) config('bawls.ban.enabled') && in_array($rule, $rules, true);
    }

    /**
     * What sets a rule off, with its configured thresholds.
     *
     * @param  array<string, mixed>  $rule
     */
    private function rule(string $name, array $rule): string
    {
        $window = $this->duration((int) ($rule['window'] ?? 0));

        return match ($name) {
            'port_scan' => "One address tried {$rule['distinct_ports']} or more different ports on a host within {$window}.",
            'host_sweep' => "One address reached {$rule['distinct_hosts']} or more of your hosts within {$window}.",
            'flood' => "{$rule['events']} or more events from one address within {$window}.",
            'brute_force' => "{$rule['attempts']} or more connections to a login service (SSH, RDP, databases) from one address within {$window}.",
            'web_exploit' => 'An attack payload sent to the decoy or one of your sites: one is enough.',
            'web_scan' => "One address asked the decoy for {$rule['distinct_paths']} or more different pages within {$window}.",
            default => str_replace('_', ' ', ucfirst($name)).'.',
        };
    }

    private function duration(int $seconds): string
    {
        return match (true) {
            $seconds % 3600 === 0 && $seconds >= 3600 => ($seconds / 3600).' hour'.($seconds === 3600 ? '' : 's'),
            $seconds % 60 === 0 && $seconds >= 60 => ($seconds / 60).' minute'.($seconds === 60 ? '' : 's'),
            default => "{$seconds} seconds",
        };
    }
}
