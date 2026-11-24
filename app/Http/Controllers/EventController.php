<?php

namespace App\Http\Controllers;

use App\Models\Event;
use App\Models\IpIntel;
use App\Services\Bans;
use App\Services\Blocklist;
use App\Services\DisplayFilter;
use App\Services\Glossary;
use App\Services\Settings;
use Illuminate\Http\JsonResponse;

/**
 * One event for the stream's details pane, grouped like Wireshark's packet
 * details. Each field that maps to a display-filter field carries the filter
 * that selects it, so the pane can offer "filter" and "exclude".
 */
class EventController extends Controller
{
    public function show(Event $event, Settings $settings, Glossary $glossary): JsonResponse
    {
        $event->load('sensor');
        $raw = $event->raw ?? [];
        $intel = IpIntel::query()->where('ip', $event->src_ip)->first();
        $banned = Bans::find($event->src_ip) !== null;

        $sections = [
            $this->section('Frame', [
                $this->field('No.', $event->id, 'no'),
                $this->field('Time · '.$settings->timezoneLabel(), $settings->local($event->occurred_at)->format('Y-m-d H:i:s')),
                // The UTC time too, unless that's what the line above already says.
                $this->field('Time · UTC', $settings->timezone() === 'UTC' ? null : $event->occurred_at->copy()->utc()->format('Y-m-d H:i:s')),
                $this->field('Sensor', $event->sensor?->name),
                $this->field('Host', $event->host),
            ]),
            $this->section('Network', [
                $this->field('Source', $event->src_ip, 'src'),
                $this->field('Source port', $event->src_port, 'src.port'),
                $this->field('Destination', $event->dst_ip, 'dst'),
                $this->field('Destination port', $event->dst_port, 'dst.port'),
                $this->field('Protocol', $event->proto, 'proto'),
                $this->field('Direction', $event->direction, 'dir'),
                $this->field('Action', $event->action, 'action'),
                $this->field('Interface', $event->iface),
            ]),
        ];

        if ($event->isHttp()) {
            $login = $event->isLoginAttempt();
            $site = $raw['site'] ?? 'decoy';
            $sections[] = $this->section('HTTP', [
                $this->field('Site', $site, 'site'),
                $this->field('Method', $raw['method'] ?? null, 'method'),
                $this->field('Path', $raw['path'] ?? null, 'path'),
                $this->field('Query', $raw['query'] ?? null, 'query'),
                $this->field('Version', $raw['http_version'] ?? null),
                $this->field('Host', $raw['host'] ?? null, 'http.host'),
                $this->field('User agent', $raw['user_agent'] ?? null, 'ua'),
                $this->field('Referer', $raw['referer'] ?? null, 'referer'),
                $this->field('Fingerprint', $raw['http_fingerprint'] ?? null),
                $this->field('Body', $raw['body_excerpt'] ?? null),
            ]);
            $sections[] = $this->section('Headers, in the order sent', array_map(
                fn (string $name): array => $this->field($name, $this->text($raw['headers'][$name] ?? null)),
                $this->headerOrder($raw),
            ));
            $sections[] = $this->section('Form', array_map(
                fn (string $name): array => $this->field($name, $this->text($raw['form'][$name])),
                is_array($raw['form'] ?? null) ? array_map('strval', array_keys($raw['form'])) : [],
            ));
            $signature = $raw['signature'] ?? 'benign';
            $meaning = $glossary->all()['signatures'][$signature] ?? null;
            // The glossary speaks for the decoy; a real site's hits ban only
            // when site bans are on.
            $crossSite = (bool) ($raw['cross_site'] ?? false);
            $bans = $meaning && $meaning['bans'] && ! $crossSite && ($event->source !== 'site_http' || Blocklist::siteBans());
            $sections[] = $this->section('Detection', [
                $this->field('Signature', $signature, 'sig'),
                $this->field('Meaning', $meaning ? $meaning['text'].($bans ? ' Bans the address.' : '') : null),
                $this->field('Login attempt', $login ? 'yes' : null, filter: 'login'),
                $this->field('Cross-site', $crossSite ? 'yes: a browser sent this from another site\'s page, so it doesn\'t ban' : null),
                $this->field($site === 'decoy' ? 'Decoy answered' : 'Site answered', $raw['status'] ?? null, 'status'),
                $this->field('Decoy page', $raw['decoy'] ?? null),
                $this->field('Flood requests folded in', $raw['suppressed'] ?? null),
            ]);
        }

        $sections[] = $this->section('Source', [
            $this->field('Country', $intel?->country, 'country'),
            $this->field('City', $intel?->city),
            $this->field('ASN', $intel?->asn, 'asn'),
            $this->field('Network', $intel?->as_org, 'org'),
            $this->field('Reverse DNS', $intel?->rdns),
            $this->field('Abuse score', $intel?->abuse_score !== null ? "{$intel->abuse_score}% ({$intel->abuse_reports} reports)" : null),
            $this->field('Tor exit', $intel?->tor_exit ? 'yes' : null),
            $this->field('Banned now', $banned ? 'yes' : 'no', filter: $banned ? 'banned' : '!banned'),
        ]);

        return response()->json([
            'id' => $event->id,
            'kind' => $event->kind(),
            'dossier' => "/ip/{$event->src_ip}",
            'sections' => array_values(array_filter($sections, fn (array $section): bool => $section['fields'] !== [])),
            'raw' => $raw,
        ]);
    }

    /**
     * @param  list<array{label: string, value: string|null, filter: string|null}>  $fields
     * @return array{title: string, fields: list<array{label: string, value: string, filter: string|null}>}
     */
    private function section(string $title, array $fields): array
    {
        return ['title' => $title, 'fields' => array_values(array_filter($fields, fn (array $field): bool => $field['value'] !== null))];
    }

    /**
     * A row of the pane. With a $field, its filter is `field == value`; a flag
     * such as login passes its whole $filter instead.
     *
     * @return array{label: string, value: string|null, filter: string|null}
     */
    private function field(string $label, string|int|null $value, ?string $field = null, ?string $filter = null): array
    {
        if ($value === null || $value === '') {
            return ['label' => $label, 'value' => null, 'filter' => null];
        }

        return [
            'label' => $label,
            'value' => (string) $value,
            'filter' => $filter ?? ($field !== null ? "{$field} == ".DisplayFilter::quote($value) : null),
        ];
    }

    /**
     * Header names in the order the client sent them, falling back to the
     * stored order.
     *
     * @param  array<string, mixed>  $raw
     * @return list<string>
     */
    private function headerOrder(array $raw): array
    {
        $headers = is_array($raw['headers'] ?? null) ? $raw['headers'] : [];
        $order = is_array($raw['header_order'] ?? null) ? $raw['header_order'] : array_keys($headers);

        return array_values(array_filter(array_map('strval', $order), fn (string $name): bool => array_key_exists($name, $headers)));
    }

    private function text(mixed $value): ?string
    {
        return match (true) {
            $value === null => null,
            is_scalar($value) => (string) $value,
            default => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        };
    }
}
