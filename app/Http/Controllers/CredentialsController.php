<?php

namespace App\Http\Controllers;

use App\Models\Event;
use App\Services\Settings;
use Illuminate\Database\Eloquent\Builder;
use Inertia\Inertia;
use Inertia\Response;

class CredentialsController extends Controller
{
    /** Where common login forms carry the username / password (WordPress, phpMyAdmin, Joomla, Drupal, generic). */
    private const USER_FIELDS = ['log', 'pma_username', 'username', 'user', 'name', 'email', 'login'];

    private const PASSWORD_FIELDS = ['pwd', 'pma_password', 'password', 'passwd', 'pass'];

    /** How many of the most-tried passwords the page lists. */
    private const MOST_TRIED = 12;

    public function index(Settings $settings): Response
    {
        $logins = fn () => Event::query()->loginAttempts();
        $repeats = $this->repeats($logins());

        $attempts = $logins()
            ->latest('occurred_at')
            ->limit(200)
            ->get()
            ->map(function (Event $e) use ($settings, $repeats): array {
                $form = $e->raw['form'] ?? [];
                $password = $this->firstField($form, self::PASSWORD_FIELDS);

                return [
                    'at' => $settings->stamp($e->occurred_at),
                    'ip' => $e->src_ip,
                    'path' => $e->raw['path'] ?? null,
                    'username' => $this->firstField($form, self::USER_FIELDS),
                    'password' => $password,
                    // How often this password was tried, by how many addresses (when more than once).
                    'tried' => $password !== null ? ($repeats[$password] ?? null) : null,
                    // Set when the login carried an attack (sqli, rce, …).
                    'attack' => ($e->raw['signature'] ?? 'login') === 'login' ? null : $e->raw['signature'],
                ];
            })
            ->all();

        return Inertia::render('Credentials', [
            'attempts' => $attempts,
            'mostTried' => collect($repeats)
                ->map(fn (array $seen, string $password): array => ['password' => $password, ...$seen])
                ->take(self::MOST_TRIED)
                ->values()
                ->all(),
        ]);
    }

    /**
     * Every password tried more than once, over all login attempts (not just the
     * ones listed), most tried first: password => [attempts, addresses]. A
     * masked password counts by its fingerprint, so a repeat shows without the
     * text ever being stored. Masked ones from before fingerprints carry only a
     * length, so they'd all look alike: they're left out.
     *
     * @return array<string, array{attempts: int, addresses: int}>
     */
    private function repeats(Builder $logins): array
    {
        $password = 'COALESCE('.implode(', ', array_map(
            fn (string $field): string => "NULLIF(json_extract(raw, '$.form.{$field}'), '')",
            self::PASSWORD_FIELDS,
        )).')';

        return $logins
            ->selectRaw("{$password} AS password, COUNT(*) AS attempts, COUNT(DISTINCT src_ip) AS addresses")
            ->groupBy('password')
            ->havingRaw('password IS NOT NULL AND COUNT(*) > 1')
            ->orderByDesc('attempts')
            ->orderByDesc('addresses')
            ->get()
            ->reject(fn ($row): bool => (bool) preg_match('/^\[masked:\d+ chars\]$/', (string) $row->password))
            ->mapWithKeys(fn ($row): array => [(string) $row->password => ['attempts' => (int) $row->attempts, 'addresses' => (int) $row->addresses]])
            ->all();
    }

    /**
     * @param  array<string, mixed>  $form
     * @param  array<int, string>  $fields
     */
    private function firstField(array $form, array $fields): ?string
    {
        foreach ($fields as $field) {
            if (isset($form[$field]) && $form[$field] !== '') {
                return (string) $form[$field];
            }
        }

        return null;
    }
}
