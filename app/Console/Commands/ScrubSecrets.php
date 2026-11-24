<?php

namespace App\Console\Commands;

use App\Models\Event;
use Illuminate\Console\Command;

/**
 * Masks credentials in events recorded before the sensors masked them
 * everywhere: the raw form body of a sign-in, secret query parameters,
 * Authorization, Cookie and API-key headers. The sensors do this themselves
 * now (sensors/decoy_sensor.py: mask_body, mask_query, mask_header), so this
 * only ever has work to do once after upgrading; running it again changes
 * nothing. It can go once events from before the fix have aged out (180 days
 * after the upgrade).
 */
class ScrubSecrets extends Command
{
    protected $signature = 'bawls:scrub-secrets {--dry-run : Count what would change, change nothing}';

    protected $description = 'Mask credentials left in events recorded before the sensors masked them everywhere';

    /** The sensors' SECRET_FIELD_RE (sensors/signatures.py). */
    private const SECRET_FIELD = '/pass|pwd|secret|token|api[_-]?key|auth/i';

    private const BODY_CAP = 4096;

    private const VALUE_CAP = 512;

    /** @var array<string, true> passwords kept as dictionary data, as the decoy keeps them */
    private array $common = [];

    public function handle(): int
    {
        $this->common = $this->commonPasswords();
        $changed = 0;

        Event::query()
            ->whereIn('source', Event::HTTP_SOURCES)
            ->whereNotNull('raw')
            ->chunkById(500, function ($events) use (&$changed): void {
                foreach ($events as $event) {
                    $raw = $event->raw;
                    $clean = $this->scrub($raw);
                    if ($clean === $raw) {
                        continue;
                    }
                    $changed++;
                    if (! $this->option('dry-run')) {
                        $event->raw = $clean;
                        $event->saveQuietly();
                    }
                }
            });

        $this->info(($this->option('dry-run') ? 'Would mask' : 'Masked')." credentials in {$changed} event(s).");

        return self::SUCCESS;
    }

    /**
     * @param  array<string, mixed>  $raw
     * @return array<string, mixed>
     */
    private function scrub(array $raw): array
    {
        $form = is_array($raw['form'] ?? null) ? $raw['form'] : [];
        $body = $raw['body_excerpt'] ?? null;
        if (is_string($body) && $body !== '' && ! str_starts_with($body, '[masked:')) {
            if ($form !== []) {
                // The form's own values are already masked: rebuild the body from them.
                $raw['body_excerpt'] = substr(http_build_query($form), 0, self::BODY_CAP);
            } elseif (preg_match(self::SECRET_FIELD, $body)) {
                $raw['body_excerpt'] = '[masked:'.mb_strlen($body).' chars]';
            }
        }

        foreach (['query', 'referer'] as $field) {
            if (is_string($raw[$field] ?? null)) {
                $raw[$field] = substr($this->url($raw[$field], $field === 'query'), 0, self::VALUE_CAP);
            }
        }

        if (is_array($raw['headers'] ?? null)) {
            foreach ($raw['headers'] as $name => $value) {
                if (is_string($value)) {
                    $raw['headers'][$name] = $this->header((string) $name, $value);
                }
            }
        }

        return $raw;
    }

    /** A URL (or a bare query string) with its secret parameters masked. */
    private function url(string $value, bool $bareQuery = false): string
    {
        [$base, $query] = $bareQuery ? ['', $value] : array_pad(explode('?', $value, 2), 2, null);
        if ($query === null || $query === '') {
            return $value;
        }

        $pairs = [];
        $touched = false;
        foreach (explode('&', $query) as $pair) {
            [$name, $text] = array_pad(explode('=', $pair, 2), 2, '');
            $name = urldecode($name);
            $text = urldecode($text);
            if (preg_match(self::SECRET_FIELD, $name) && ! str_starts_with($text, '[masked:') && ! isset($this->common[$text])) {
                $text = '[masked:'.mb_strlen($text).' chars]';
                $touched = true;
            }
            $pairs[] = urlencode($name).'='.urlencode($text);
        }

        // Untouched queries stay exactly as the client sent them.
        return $touched ? ($bareQuery ? '' : $base.'?').implode('&', $pairs) : $value;
    }

    private function header(string $name, string $value): string
    {
        if (str_contains($value, '[masked')) {
            return $value;
        }
        $lower = strtolower($name);

        return match (true) {
            $lower === 'referer' => substr($this->url($value), 0, self::VALUE_CAP),
            in_array($lower, ['authorization', 'proxy-authorization'], true) => $this->authorization($value),
            $lower === 'cookie' => $this->cookie($value),
            (bool) preg_match(self::SECRET_FIELD, $name) => '[masked:'.mb_strlen($value).' chars]',
            default => $value,
        };
    }

    private function authorization(string $value): string
    {
        [$scheme, $credentials] = array_pad(explode(' ', trim($value), 2), 2, '');

        return $credentials === ''
            ? '[masked:'.mb_strlen($value).' chars]'
            : substr($scheme, 0, 32).' [masked:'.mb_strlen($credentials).' chars]';
    }

    private function cookie(string $value): string
    {
        $names = [];
        foreach (explode(';', $value) as $part) {
            if (trim($part) !== '') {
                $names[] = trim(explode('=', $part, 2)[0]).'=[masked]';
            }
        }

        return substr(implode('; ', $names), 0, self::VALUE_CAP);
    }

    /**
     * @return array<string, true>
     */
    private function commonPasswords(): array
    {
        $file = base_path('sensors/common_passwords.txt');
        $lines = is_readable($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

        return array_fill_keys(array_filter($lines ?: [], fn (string $line): bool => ! str_starts_with($line, '#')), true);
    }
}
