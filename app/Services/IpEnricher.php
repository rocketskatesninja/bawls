<?php

namespace App\Services;

use App\Models\IpIntel;
use GeoIp2\Database\Reader;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Builds a dossier on an IP address from passive, public sources only.
 *
 * Nothing here connects back to, scans, or probes the address being looked up:
 * MaxMind is read from a local database, and the remaining lookups ask public
 * services what they already know. Every source is wrapped so one failing (or
 * an unset key) never stops the others, and a source that returns nothing
 * leaves the existing value untouched rather than erasing it.
 */
class IpEnricher
{
    /** @var array<string, ?Reader> MaxMind readers by file, opened on first use (null = unavailable). */
    private array $readers = [];

    /**
     * Enrich one IP and persist it. Returns the saved record, or null when the
     * value is not a usable IP address.
     */
    public function enrich(string $ip): ?IpIntel
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        if (Network::isInternal($ip)) {
            // One of ours: record that, and make no external calls about it.
            return IpIntel::updateOrCreate(
                ['ip' => $ip],
                ['is_private' => true, 'checked_at' => now()],
            );
        }

        $data = $this->geo($ip)
            + $this->asn($ip)
            + ['rdns' => $this->rdns($ip)]
            + $this->shodanInternetDb($ip)
            + ['greynoise_class' => $this->greyNoise($ip)]
            + $this->abuseIpDb($ip)
            + ['abuse_contact' => $this->rdapAbuseContact($ip)];

        // Drop sources that returned nothing this run so a transient failure
        // never overwrites good data with null.
        $data = array_filter($data, static fn ($value): bool => $value !== null);
        $data['is_private'] = false;
        $data['checked_at'] = now();

        return IpIntel::updateOrCreate(['ip' => $ip], $data);
    }

    /**
     * @return array<string, mixed>
     */
    private function geo(string $ip): array
    {
        $reader = $this->reader('GeoLite2-City.mmdb');
        if (! $reader) {
            return [];
        }
        try {
            $record = $reader->city($ip);

            return [
                'country' => $record->country->isoCode,
                'city' => $record->city->name,
                'latitude' => $record->location->latitude,
                'longitude' => $record->location->longitude,
            ];
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function asn(string $ip): array
    {
        $reader = $this->reader('GeoLite2-ASN.mmdb');
        if (! $reader) {
            return [];
        }
        try {
            $record = $reader->asn($ip);

            return [
                'asn' => $record->autonomousSystemNumber,
                'as_org' => $record->autonomousSystemOrganization,
            ];
        } catch (Throwable) {
            return [];
        }
    }

    private function rdns(string $ip): ?string
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }
        $reverse = implode('.', array_reverse(explode('.', $ip))).'.in-addr.arpa';
        try {
            $response = Http::timeout(5)
                ->withHeaders(['Accept' => 'application/dns-json'])
                ->get('https://cloudflare-dns.com/dns-query', ['name' => $reverse, 'type' => 'PTR']);

            $data = $response->ok() ? $response->json('Answer.0.data') : null;

            return is_string($data) ? rtrim($data, '.') : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function shodanInternetDb(string $ip): array
    {
        try {
            $response = Http::timeout(6)->acceptJson()->get("https://internetdb.shodan.io/{$ip}");

            if ($response->status() === 404) {
                return ['open_ports' => []];
            }
            if (! $response->ok()) {
                return [];
            }

            $tags = array_map('strtolower', (array) $response->json('tags', []));

            return [
                'open_ports' => $response->json('ports', []),
                'tor_exit' => in_array('tor', $tags, true),
            ];
        } catch (Throwable) {
            return [];
        }
    }

    private function greyNoise(string $ip): ?string
    {
        try {
            $request = Http::timeout(6)->acceptJson();
            if ($key = config('services.greynoise.key')) {
                $request = $request->withHeaders(['key' => $key]);
            }
            $response = $request->get("https://api.greynoise.io/v3/community/{$ip}");

            if ($response->status() === 404) {
                return 'unknown';   // GreyNoise has never seen it
            }
            if (! $response->ok()) {
                return null;
            }

            $class = $response->json('classification');

            return is_string($class) ? $class : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function abuseIpDb(string $ip): array
    {
        $key = config('services.abuseipdb.key');
        if (! $key) {
            return [];
        }
        try {
            $response = Http::timeout(6)
                ->withHeaders(['Key' => $key, 'Accept' => 'application/json'])
                ->get('https://api.abuseipdb.com/api/v2/check', ['ipAddress' => $ip, 'maxAgeInDays' => 90]);

            if (! $response->ok()) {
                return [];
            }

            return [
                'abuse_score' => $response->json('data.abuseConfidenceScore'),
                'abuse_reports' => $response->json('data.totalReports'),
            ];
        } catch (Throwable) {
            return [];
        }
    }

    private function rdapAbuseContact(string $ip): ?string
    {
        try {
            $response = Http::timeout(6)->acceptJson()->get("https://rdap.org/ip/{$ip}");
            if (! $response->ok()) {
                return null;
            }

            return $this->findAbuse((array) $response->json('entities', []));
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Walk the RDAP entity tree for an abuse contact's email (or handle).
     *
     * @param  array<int, array<string, mixed>>  $entities
     */
    private function findAbuse(array $entities): ?string
    {
        foreach ($entities as $entity) {
            if (in_array('abuse', (array) ($entity['roles'] ?? []), true)) {
                return $this->vcardEmail($entity) ?? ($entity['handle'] ?? null);
            }
            if ($nested = $this->findAbuse((array) ($entity['entities'] ?? []))) {
                return $nested;
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $entity
     */
    private function vcardEmail(array $entity): ?string
    {
        foreach ((array) ($entity['vcardArray'][1] ?? []) as $field) {
            if (($field[0] ?? null) === 'email') {
                return $field[3] ?? null;
            }
        }

        return null;
    }

    private function reader(string $file): ?Reader
    {
        if (! array_key_exists($file, $this->readers)) {
            $path = rtrim((string) config('services.maxmind.db_path'), '/').'/'.$file;
            try {
                $this->readers[$file] = is_file($path) ? new Reader($path) : null;
            } catch (Throwable) {
                $this->readers[$file] = null;
            }
        }

        return $this->readers[$file];
    }
}
