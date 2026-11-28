<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Models\User;
use App\Services\IpEnricher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class IpDossierTest extends TestCase
{
    use RefreshDatabase;

    private function hit(Sensor $sensor, string $srcIp, string $source = 'honeypot_http', ?array $raw = null): void
    {
        Event::create([
            'occurred_at' => now(),
            'sensor_id' => $sensor->id,
            'host' => 'web1',
            'source' => $source,
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => $srcIp,
            'dst_ip' => '10.0.0.80',
            'dst_port' => 8088,
            'action' => $source === 'honeypot_http' ? 'probed' : 'blocked',
            'raw' => $raw,
        ]);
    }

    public function test_the_console_is_not_reachable_anonymously(): void
    {
        $this->get('/ip')->assertNotFound();
        $this->get('/ip/203.0.113.5')->assertNotFound();
    }

    public function test_the_index_lists_external_ips_and_excludes_private_ones(): void
    {
        $sensor = Sensor::factory()->create();
        $this->hit($sensor, '203.0.113.5', 'honeypot_http', ['path' => '/.env', 'signature' => 'dirbust']);
        $this->hit($sensor, '192.168.1.5', 'honeypot_http', ['path' => '/', 'signature' => 'benign']);

        $this->signIn()
            ->get('/ip')
            ->assertInertia(fn (Assert $page) => $page
                ->component('IpDossier', false)
                ->where('selected', null)
                ->has('ips', 1)
                ->where('ips.0.ip', '203.0.113.5')
                ->where('ips.0.signature', 'dirbust')
            );
    }

    public function test_filters_find_matches_older_than_the_newest_300_addresses(): void
    {
        $sensor = Sensor::factory()->create();
        // The oldest address did the interesting thing...
        Event::create([
            'occurred_at' => now()->subDays(3), 'sensor_id' => $sensor->id, 'host' => 'web1',
            'source' => 'honeypot_http', 'direction' => 'in', 'proto' => 'tcp', 'src_ip' => '198.51.100.7',
            'dst_ip' => '10.0.0.80', 'dst_port' => 8088, 'action' => 'probed',
            'raw' => ['path' => '/?id=1 union select', 'signature' => 'sqli'],
        ]);
        IpIntel::create(['ip' => '198.51.100.7', 'is_private' => false, 'country' => 'NL', 'checked_at' => now()]);
        Alert::factory()->seen(now()->subDays(3))->create(['src_ip' => '198.51.100.7', 'status' => 'acked']);
        // ...then 300 newer addresses push it past the list's cap.
        Event::insert(collect(range(1, 300))->map(fn (int $i): array => [
            'occurred_at' => now()->subMinutes($i), 'sensor_id' => $sensor->id, 'host' => 'web1',
            'source' => 'honeypot_http', 'direction' => 'in', 'proto' => 'tcp',
            'src_ip' => '203.0.'.intdiv($i, 250).'.'.($i % 250 + 1), 'dst_ip' => '10.0.0.80', 'dst_port' => 8088,
            'action' => 'probed', 'raw' => json_encode(['path' => '/', 'signature' => 'benign']),
        ])->all());

        $user = User::factory()->create();
        $this->actingAs($user)->get('/ip')
            ->assertInertia(fn (Assert $page) => $page->has('ips', 300)->where('ips.299.ip', fn ($ip): bool => $ip !== '198.51.100.7'));

        foreach (['alerts=1', 'country=nl', 'signature=sqli', 'q=198.51'] as $filter) {
            $this->actingAs($user)->get("/ip?{$filter}")
                ->assertInertia(fn (Assert $page) => $page
                    ->has('ips', 1)
                    ->where('ips.0.ip', '198.51.100.7')
                    ->where('ips.0.alert_severity', 5));    // an acked alert still marks it
        }
    }

    public function test_the_detail_shows_intel_timeline_and_alerts(): void
    {
        $sensor = Sensor::factory()->create();
        $this->hit($sensor, '203.0.113.5', 'honeypot_http', ['path' => '/wp-login.php', 'method' => 'POST', 'signature' => 'login']);
        IpIntel::create(['ip' => '203.0.113.5', 'is_private' => false, 'country' => 'DE', 'asn' => 64500, 'as_org' => 'Example AS', 'checked_at' => now()]);
        Alert::factory()->create(['title' => 'Exploit attempt', 'src_ip' => '203.0.113.5']);

        $this->signIn()
            ->get('/ip/203.0.113.5')
            ->assertInertia(fn (Assert $page) => $page
                ->component('IpDossier', false)
                ->where('selected.ip', '203.0.113.5')
                ->where('selected.intel.country', 'DE')
                ->has('selected.timeline', 1)
                ->has('selected.alerts', 1)
                ->where('selected.alerts.0.rule', 'web_exploit')
            );
    }

    public function test_the_summary_gives_the_verdict_worst_first(): void
    {
        $this->fakeBans(['203.0.113.5' => ['2026-11-18 07:54:00', '2026-11-25 07:54:00']]);
        $sensor = Sensor::factory()->create();
        $this->hit($sensor, '203.0.113.5', 'honeypot_http', ['path' => '/.env', 'method' => 'GET', 'signature' => 'sqli']);
        $this->hit($sensor, '203.0.113.5', 'honeypot_http', ['path' => '/x', 'method' => 'GET', 'signature' => 'cve_probe']);
        $this->hit($sensor, '203.0.113.5', 'honeypot_http', ['path' => '/wp-login.php', 'method' => 'POST', 'signature' => 'login', 'login_attempt' => true]);
        IpIntel::create(['ip' => '203.0.113.5', 'is_private' => false, 'abuse_score' => 90, 'tor_exit' => true, 'checked_at' => now()]);

        $summary = $this->signIn()->get('/ip/203.0.113.5')->viewData('page')['props']['selected']['summary'];

        $this->assertSame([
            'Banned until Nov 25 07:54', '2 exploit attempts', '1 password guess', '3 events within a minute', 'AbuseIPDB 90%', 'Tor exit',
        ], array_column($summary, 'text'));
        $this->assertSame('alarm', $summary[0]['tone']);
    }

    public function test_a_bogus_ip_in_the_url_is_rejected(): void
    {
        // The route constraint only allows hex/dot/colon; anything else 404s.
        $this->signIn()->get('/ip/not-an-ip!')->assertNotFound();
    }

    public function test_the_client_analysis_flags_a_spoofed_user_agent(): void
    {
        // A browser User-Agent with none of the headers a real browser sends.
        $sensor = Sensor::factory()->create();
        $this->hit($sensor, '203.0.113.9', 'honeypot_http', [
            'path' => '/', 'method' => 'GET', 'signature' => 'dirbust',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
            'http_fingerprint' => 'abc123def456aaaa', 'header_order' => ['Host', 'User-Agent'],
        ]);

        $this->signIn()
            ->get('/ip/203.0.113.9')
            ->assertInertia(fn (Assert $page) => $page
                ->where('selected.client.http_fingerprint', 'abc123def456aaaa')
                ->where('selected.client.assessment.verdict', 'spoofed')
                ->where('selected.client.assessment.text', fn ($v): bool => str_contains((string) $v, 'spoofed User-Agent'))
            );
    }

    public function test_look_up_now_enriches_the_address_at_once_even_when_fresh(): void
    {
        IpIntel::create(['ip' => '203.0.113.9', 'checked_at' => now()]);
        $asked = [];
        $this->mock(IpEnricher::class, function ($mock) use (&$asked): void {
            $mock->shouldReceive('enrich')->andReturnUsing(function (string $ip) use (&$asked): IpIntel {
                $asked[] = $ip;

                return IpIntel::updateOrCreate(['ip' => $ip], ['country' => 'DE', 'checked_at' => now()]);
            });
        });

        $this->signIn()->from('/ip/203.0.113.9')
            ->post('/ip/203.0.113.9/enrich')
            ->assertRedirect('/ip/203.0.113.9')
            ->assertSessionHasNoErrors();

        $this->assertSame(['203.0.113.9'], $asked);
        $this->assertSame('DE', IpIntel::where('ip', '203.0.113.9')->value('country'));
    }

    public function test_look_up_now_needs_a_sign_in_and_is_capped_per_minute(): void
    {
        $this->post('/ip/203.0.113.9/enrich')->assertNotFound();

        $calls = 0;
        $this->mock(IpEnricher::class, function ($mock) use (&$calls): void {
            $mock->shouldReceive('enrich')->andReturnUsing(function (string $ip) use (&$calls): IpIntel {
                $calls++;

                return IpIntel::updateOrCreate(['ip' => $ip], ['checked_at' => now()]);
            });
        });

        $this->signIn();
        for ($i = 0; $i < 10; $i++) {
            $this->post('/ip/203.0.113.9/enrich')->assertSessionHasNoErrors();
        }
        $this->post('/ip/203.0.113.9/enrich')->assertSessionHasErrors('enrich');

        $this->assertSame(10, $calls);
    }
}
