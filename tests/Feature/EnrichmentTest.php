<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Services\IpEnricher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class EnrichmentTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // Keep tests off the local GeoIP database so geo/ASN are deterministic
        // (absent) regardless of whether the .mmdb has been downloaded.
        config(['services.maxmind.db_path' => '/nonexistent']);
    }

    private function fakeSources(): void
    {
        Http::fake([
            'cloudflare-dns.com/*' => Http::response(['Answer' => [['data' => 'scanner.example.']]]),
            'internetdb.shodan.io/*' => Http::response(['ports' => [22, 80, 443], 'tags' => ['tor']]),
            'api.greynoise.io/*' => Http::response(['classification' => 'malicious', 'noise' => true]),
            'rdap.org/*' => Http::response(['entities' => [[
                'roles' => ['abuse'],
                'vcardArray' => ['vcard', [['version', [], 'text', '4.0'], ['email', [], 'text', 'abuse@evil.example']]],
            ]]]),
            'api.abuseipdb.com/*' => Http::response(['data' => ['abuseConfidenceScore' => 87, 'totalReports' => 42]]),
        ]);
    }

    public function test_a_private_ip_is_marked_and_never_looked_up(): void
    {
        Http::fake();

        $intel = app(IpEnricher::class)->enrich('10.0.0.50');

        $this->assertTrue($intel->is_private);
        Http::assertNothingSent();
    }

    public function test_it_maps_fields_from_passive_sources(): void
    {
        config(['services.abuseipdb.key' => 'test-key']);
        $this->fakeSources();

        $intel = app(IpEnricher::class)->enrich('203.0.113.77');

        $this->assertFalse($intel->is_private);
        $this->assertSame('scanner.example', $intel->rdns);
        $this->assertSame([22, 80, 443], $intel->open_ports);
        $this->assertTrue($intel->tor_exit);
        $this->assertSame('malicious', $intel->greynoise_class);
        $this->assertSame('abuse@evil.example', $intel->abuse_contact);
        $this->assertSame(87, $intel->abuse_score);
        $this->assertSame(42, $intel->abuse_reports);
    }

    public function test_abuseipdb_is_skipped_without_a_key(): void
    {
        config(['services.abuseipdb.key' => null]);
        $this->fakeSources();

        $intel = app(IpEnricher::class)->enrich('203.0.113.78');

        $this->assertNull($intel->abuse_score);
        Http::assertNotSent(fn ($request): bool => str_contains($request->url(), 'abuseipdb'));
    }

    public function test_the_command_enriches_only_suspicious_external_ips(): void
    {
        $this->fakeSources();
        $sensor = Sensor::factory()->create();

        $this->event($sensor, '203.0.113.10', 'honeypot_http', 'probed', ['signature' => 'sqli', 'path' => '/x']);
        $this->event($sensor, '203.0.113.20', 'honeypot_http', 'probed', ['signature' => 'benign', 'path' => '/']);
        $this->event($sensor, '203.0.113.30', 'honeypot_http', 'probed', ['signature' => 'browser_check', 'path' => '/browser-check']);
        $this->event($sensor, '198.51.100.5', 'ufw_block', 'blocked', null);
        $this->event($sensor, '10.0.0.9', 'honeypot_http', 'probed', ['signature' => 'sqli', 'path' => '/x']);

        $this->artisan('bawls:enrich')->assertSuccessful();

        $this->assertTrue(IpIntel::where('ip', '203.0.113.10')->exists(), 'suspicious hit enriched');
        $this->assertTrue(IpIntel::where('ip', '198.51.100.5')->exists(), 'firewall block enriched');
        $this->assertFalse(IpIntel::where('ip', '203.0.113.20')->exists(), 'benign hit left alone');
        $this->assertFalse(IpIntel::where('ip', '203.0.113.30')->exists(), 'browser-check volunteer left alone');
        $this->assertFalse(IpIntel::where('ip', '10.0.0.9')->exists(), 'private IP skipped');
    }

    public function test_a_freshly_checked_ip_is_not_re_enriched(): void
    {
        $this->fakeSources();
        $sensor = Sensor::factory()->create();
        IpIntel::create(['ip' => '203.0.113.30', 'checked_at' => now()->subDay()]);
        $this->event($sensor, '203.0.113.30', 'honeypot_http', 'probed', ['signature' => 'sqli', 'path' => '/x']);

        $this->artisan('bawls:enrich')->assertSuccessful();

        // Untouched: still no greynoise_class from this run.
        $this->assertNull(IpIntel::where('ip', '203.0.113.30')->first()->greynoise_class);
    }

    public function test_geo_is_read_from_the_local_database_when_present(): void
    {
        if (! is_file(storage_path('geoip/GeoLite2-City.mmdb'))) {
            $this->markTestSkipped('GeoLite2 database not downloaded');
        }
        config(['services.maxmind.db_path' => storage_path('geoip'), 'services.abuseipdb.key' => null]);
        Http::fake();

        $intel = app(IpEnricher::class)->enrich('8.8.8.8');

        $this->assertSame('US', $intel->country);
        $this->assertSame(15169, $intel->asn);
    }

    /**
     * @param  array<string, mixed>|null  $raw
     */
    private function event(Sensor $sensor, string $srcIp, string $source, string $action, ?array $raw): void
    {
        Event::create([
            'occurred_at' => now(),
            'sensor_id' => $sensor->id,
            'host' => 'web1',
            'source' => $source,
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => $srcIp,
            'dst_ip' => '10.0.0.1',
            'action' => $action,
            'raw' => $raw,
        ]);
    }
}
