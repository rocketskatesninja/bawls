<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Models\User;
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
            'dst_ip' => '192.168.0.80',
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

        $this->actingAs(User::factory()->create())
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
            'dst_ip' => '192.168.0.80', 'dst_port' => 8088, 'action' => 'probed',
            'raw' => ['path' => '/?id=1 union select', 'signature' => 'sqli'],
        ]);
        IpIntel::create(['ip' => '198.51.100.7', 'is_private' => false, 'country' => 'NL', 'checked_at' => now()]);
        Alert::create([
            'rule' => 'web_exploit', 'severity' => 5, 'title' => 'x', 'src_ip' => '198.51.100.7', 'host' => 'web1',
            'first_seen_at' => now()->subDays(3), 'last_seen_at' => now()->subDays(3), 'event_count' => 1, 'status' => 'acked',
        ]);
        // ...then 300 newer addresses push it past the list's cap.
        Event::insert(collect(range(1, 300))->map(fn (int $i): array => [
            'occurred_at' => now()->subMinutes($i), 'sensor_id' => $sensor->id, 'host' => 'web1',
            'source' => 'honeypot_http', 'direction' => 'in', 'proto' => 'tcp',
            'src_ip' => '203.0.'.intdiv($i, 250).'.'.($i % 250 + 1), 'dst_ip' => '192.168.0.80', 'dst_port' => 8088,
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
        Alert::create([
            'rule' => 'web_exploit', 'severity' => 5, 'title' => 'Exploit attempt', 'src_ip' => '203.0.113.5',
            'host' => 'web1', 'first_seen_at' => now(), 'last_seen_at' => now(), 'event_count' => 1, 'status' => 'open',
        ]);

        $this->actingAs(User::factory()->create())
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

    public function test_a_bogus_ip_in_the_url_is_rejected(): void
    {
        // The route constraint only allows hex/dot/colon; anything else 404s.
        $this->actingAs(User::factory()->create())->get('/ip/not-an-ip!')->assertNotFound();
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

        $this->actingAs(User::factory()->create())
            ->get('/ip/203.0.113.9')
            ->assertInertia(fn (Assert $page) => $page
                ->where('selected.client.http_fingerprint', 'abc123def456aaaa')
                ->where('selected.client.assessment.verdict', 'spoofed')
                ->where('selected.client.assessment.text', fn ($v): bool => str_contains((string) $v, 'spoofed User-Agent'))
            );
    }
}
