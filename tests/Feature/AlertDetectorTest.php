<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\Sensor;
use App\Services\AlertDetector;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class AlertDetectorTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sensor = Sensor::factory()->create(['host' => 'web1']);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function events(int $count, array $attributes, ?callable $vary = null): void
    {
        for ($i = 0; $i < $count; $i++) {
            Event::factory()->create(array_merge(
                ['sensor_id' => $this->sensor->id, 'host' => 'web1', 'occurred_at' => now()->subSeconds(30)],
                $attributes,
                $vary ? $vary($i) : [],
            ));
        }
    }

    public function test_it_flags_a_port_scan(): void
    {
        $this->events(20, ['src_ip' => '203.0.113.7', 'dst_ip' => '10.0.0.101'],
            fn (int $i): array => ['dst_port' => 1000 + $i]);

        $this->assertGreaterThan(0, (new AlertDetector)->run());

        $alert = Alert::where('rule', 'port_scan')->sole();
        $this->assertSame('203.0.113.7', $alert->src_ip);
        $this->assertSame(20, $alert->details['distinct_ports']);
        $this->assertSame('open', $alert->status);
    }

    public function test_it_ignores_a_port_scan_below_threshold(): void
    {
        $this->events(5, ['src_ip' => '203.0.113.7', 'dst_ip' => '10.0.0.101'],
            fn (int $i): array => ['dst_port' => 1000 + $i]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::where('rule', 'port_scan')->count());
    }

    public function test_it_flags_brute_force_on_an_auth_port(): void
    {
        $this->events(15, ['src_ip' => '198.51.100.3', 'dst_ip' => '10.0.0.101', 'dst_port' => 22]);

        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'brute_force')->sole();
        $this->assertSame(22, $alert->details['port']);
        $this->assertSame(4, $alert->severity);
    }

    public function test_it_does_not_flag_brute_force_on_a_non_auth_port(): void
    {
        $this->events(15, ['src_ip' => '198.51.100.3', 'dst_ip' => '10.0.0.101', 'dst_port' => 8123]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::where('rule', 'brute_force')->count());
    }

    public function test_it_ignores_multicast_chatter_for_the_flood_rule(): void
    {
        // The router emits IGMP to 224.0.0.1 constantly; without the ignore
        // list this alone would trip the flood rule every single window.
        $this->events(600, ['src_ip' => '10.0.0.254', 'dst_ip' => '224.0.0.1', 'dst_port' => null]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::where('rule', 'flood')->count());
    }

    public function test_it_flags_a_genuine_flood(): void
    {
        $this->events(600, [
            'src_ip' => '203.0.113.50',
            'dst_ip' => '10.0.0.101',
            'dst_port' => 80,
            'occurred_at' => now()->subSeconds(10),
        ]);

        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'flood')->sole();
        $this->assertSame('203.0.113.50', $alert->src_ip);
        $this->assertGreaterThanOrEqual(600, $alert->details['events_in_window']);
    }

    public function test_a_sustained_attack_updates_one_alert_instead_of_duplicating(): void
    {
        $this->events(20, ['src_ip' => '203.0.113.7', 'dst_ip' => '10.0.0.101'],
            fn (int $i): array => ['dst_port' => 1000 + $i]);

        (new AlertDetector)->run();
        (new AlertDetector)->run();
        (new AlertDetector)->run();

        $this->assertSame(1, Alert::where('rule', 'port_scan')->count());
    }

    public function test_it_ignores_events_outside_the_window(): void
    {
        $this->events(20, [
            'src_ip' => '203.0.113.7',
            'dst_ip' => '10.0.0.101',
            'occurred_at' => now()->subHours(2),
        ], fn (int $i): array => ['dst_port' => 1000 + $i]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::count());
    }

    public function test_it_ignores_outbound_traffic(): void
    {
        $this->events(20, [
            'src_ip' => '10.0.0.101',
            'dst_ip' => '203.0.113.7',
            'direction' => 'out',
        ], fn (int $i): array => ['dst_port' => 1000 + $i]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::count());
    }

    public function test_it_flags_a_web_scan_across_many_decoy_paths(): void
    {
        $this->events(12, [
            'src_ip' => '203.0.113.80', 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed',
        ], fn (int $i): array => ['raw' => ['path' => '/p'.$i, 'signature' => 'dirbust']]);

        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'web_scan')->sole();
        $this->assertSame('203.0.113.80', $alert->src_ip);
        $this->assertSame(12, $alert->details['distinct_paths']);
    }

    public function test_it_flags_an_exploit_attempt_on_the_decoy(): void
    {
        $this->events(3, [
            'src_ip' => '203.0.113.81', 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed',
        ], fn (int $i): array => ['raw' => ['path' => '/x'.$i, 'signature' => 'sqli']]);

        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'web_exploit')->sole();
        $this->assertSame(5, $alert->severity);
        $this->assertSame(3, $alert->details['attempts']);
    }

    public function test_benign_decoy_hits_do_not_trip_the_exploit_rule(): void
    {
        $this->events(5, [
            'src_ip' => '203.0.113.82', 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed',
        ], fn (int $i): array => ['raw' => ['path' => '/', 'signature' => 'benign']]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::where('rule', 'web_exploit')->count());
    }

    /**
     * @param  array<string, mixed>  $raw
     */
    private function decoyHits(string $ip, int $count, array $raw, int $secondsAgo = 30): void
    {
        $this->events($count, [
            'src_ip' => $ip, 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed', 'occurred_at' => now()->subSeconds($secondsAgo),
        ], fn (int $i): array => ['raw' => $raw + ['path' => '/x'.$i]]);
    }

    public function test_an_acknowledged_alert_keeps_accumulating_instead_of_duplicating(): void
    {
        $this->decoyHits('203.0.113.60', 2, ['signature' => 'sqli'], 120);
        (new AlertDetector)->run();
        Alert::where('rule', 'web_exploit')->sole()->update(['status' => 'acked']);

        $this->decoyHits('203.0.113.60', 3, ['signature' => 'rce']);
        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'web_exploit')->sole();
        $this->assertSame('acked', $alert->status);
        $this->assertSame(5, $alert->event_count);
    }

    public function test_a_resolved_alert_lets_a_returning_attacker_open_a_fresh_one(): void
    {
        $this->decoyHits('203.0.113.61', 2, ['signature' => 'sqli'], 120);
        (new AlertDetector)->run();
        Alert::where('rule', 'web_exploit')->sole()->update(['status' => 'resolved']);

        $this->decoyHits('203.0.113.61', 1, ['signature' => 'sqli']);
        (new AlertDetector)->run();

        $this->assertSame(['open', 'resolved'],
            Alert::where('rule', 'web_exploit')->orderBy('status')->pluck('status')->all());
    }

    public function test_resolving_an_alert_doesnt_bring_it_back_from_the_same_requests(): void
    {
        // Resolved a minute after the attack: its requests are still inside
        // the rule's 10-minute window when the detector next runs.
        $this->decoyHits('203.0.113.65', 1, ['signature' => 'sqli'], 60);
        (new AlertDetector)->run();
        Alert::where('rule', 'web_exploit')->sole()->update(['status' => 'resolved']);

        (new AlertDetector)->run();
        (new AlertDetector)->run();

        $this->assertSame(['resolved'], Alert::where('rule', 'web_exploit')->pluck('status')->all());
    }

    public function test_ignored_sources_never_alert_on_any_rule(): void
    {
        config(['bawls.ignore.src' => ['203.0.113.0/24']]);

        $this->decoyHits('203.0.113.62', 3, ['signature' => 'sqli']);          // web_exploit
        $this->decoyHits('203.0.113.63', 12, ['signature' => 'dirbust']);      // web_scan
        $this->events(16, ['src_ip' => '203.0.113.64', 'dst_ip' => '198.51.100.1'],   // port_scan
            fn (int $i): array => ['dst_port' => 2000 + $i]);

        (new AlertDetector)->run();

        $this->assertSame(0, Alert::count());
    }

    public function test_a_new_high_severity_alert_fires_the_webhook(): void
    {
        config(['bawls.alert.webhook' => 'https://hook.example/notify', 'bawls.alert.min_severity' => 4]);
        Http::fake();

        $this->events(3, [
            'src_ip' => '203.0.113.90', 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed',
        ], fn (int $i): array => ['raw' => ['path' => '/x'.$i, 'signature' => 'sqli']]);

        (new AlertDetector)->run();

        Http::assertSent(fn ($r): bool => str_contains($r->url(), 'hook.example') && $r['rule'] === 'web_exploit');
    }

    public function test_a_low_severity_alert_does_not_fire_the_webhook(): void
    {
        config(['bawls.alert.webhook' => 'https://hook.example/notify', 'bawls.alert.min_severity' => 4]);
        Http::fake();

        // web_scan is severity 3, below the threshold.
        $this->events(12, [
            'src_ip' => '203.0.113.91', 'dst_ip' => '10.0.0.80', 'dst_port' => 80,
            'source' => 'honeypot_http', 'action' => 'probed',
        ], fn (int $i): array => ['raw' => ['path' => '/p'.$i, 'signature' => 'dirbust']]);

        (new AlertDetector)->run();

        Http::assertNothingSent();
    }
}
