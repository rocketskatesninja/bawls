<?php

namespace App\Http\Controllers;

use App\Models\Event;
use App\Services\Settings;
use Inertia\Inertia;
use Inertia\Response;

class CredentialsController extends Controller
{
    /** Where common login forms carry the username / password (WordPress, phpMyAdmin, Joomla, Drupal, generic). */
    private const USER_FIELDS = ['log', 'pma_username', 'username', 'user', 'name', 'email', 'login'];

    private const PASSWORD_FIELDS = ['pwd', 'pma_password', 'password', 'passwd', 'pass'];

    public function index(Settings $settings): Response
    {
        // Every POST to a login path, whatever its signature: a login carrying a
        // payload (admin' OR 1=1--) is classified sqli but is still a login.
        // signature=login covers rows recorded before the decoy set the flag.
        $attempts = Event::query()
            ->where('source', 'honeypot_http')
            ->where(fn ($q) => $q->where('raw->login_attempt', true)->orWhere('raw->signature', 'login'))
            ->latest('occurred_at')
            ->limit(200)
            ->get()
            ->map(function (Event $e) use ($settings): array {
                $form = $e->raw['form'] ?? [];

                return [
                    'at' => $settings->local($e->occurred_at)->format('M j H:i:s'),
                    'ip' => $e->src_ip,
                    'path' => $e->raw['path'] ?? null,
                    'username' => $this->firstField($form, self::USER_FIELDS),
                    'password' => $this->firstField($form, self::PASSWORD_FIELDS),
                    // Set when the login carried an attack (sqli, rce, …).
                    'attack' => ($e->raw['signature'] ?? 'login') === 'login' ? null : $e->raw['signature'],
                ];
            })
            ->all();

        return Inertia::render('Credentials', ['attempts' => $attempts]);
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
