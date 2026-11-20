<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class PruneTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sensor = Sensor::factory()->create();
    }

    private function event(string $srcIp, int $daysAgo, ?string $signature): Event
    {
        return Event::create([
            'occurred_at' => now()->subDays($daysAgo),
            'sensor_id' => $this->sensor->id,
            'host' => 'web1',
            'source' => 'honeypot_http',
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => $srcIp,
            'dst_ip' => '192.168.0.80',
            'dst_port' => 8088,
            'action' => 'probed',
            'raw' => $signature ? ['path' => '/', 'signature' => $signature] : ['path' => '/'],
        ]);
    }

    public function test_it_keeps_recent_noise_but_drops_old_noise(): void
    {
        $recent = $this->event('203.0.113.1', 3, 'benign');
        $old = $this->event('203.0.113.2', 10, 'benign');
        // A volunteer's disclosed browser-check result is not attacker evidence.
        $oldCheck = $this->event('203.0.113.5', 10, 'browser_check');

        $this->artisan('bawls:prune')->assertSuccessful();

        $this->assertModelExists($recent);
        $this->assertModelMissing($old);
        $this->assertModelMissing($oldCheck);
    }

    public function test_it_keeps_old_attacker_evidence(): void
    {
        // A non-benign signature survives well past the benign window...
        $probe = $this->event('203.0.113.3', 30, 'sqli');
        // ...and so does a benign hit from an IP that raised an alert.
        $benignFromBadIp = $this->event('203.0.113.4', 30, 'benign');
        Alert::create([
            'rule' => 'web_exploit', 'severity' => 5, 'title' => 'x', 'src_ip' => '203.0.113.4',
            'host' => 'web1', 'first_seen_at' => now(), 'last_seen_at' => now(), 'event_count' => 1, 'status' => 'open',
        ]);

        $this->artisan('bawls:prune')->assertSuccessful();

        $this->assertModelExists($probe);
        $this->assertModelExists($benignFromBadIp);
    }

    public function test_even_evidence_expires_at_the_long_window(): void
    {
        $ancient = $this->event('203.0.113.5', 200, 'sqli');

        $this->artisan('bawls:prune')->assertSuccessful();

        $this->assertModelMissing($ancient);
    }

    public function test_orphaned_ip_intel_is_pruned_but_intel_with_events_is_kept(): void
    {
        $this->event('203.0.113.7', 2, 'sqli');                 // keeps its intel
        IpIntel::create(['ip' => '203.0.113.7', 'country' => 'US', 'checked_at' => now()]);
        IpIntel::create(['ip' => '198.51.100.9', 'country' => 'DE', 'checked_at' => now()]);  // orphan: no events

        $this->artisan('bawls:prune')->assertSuccessful();

        $this->assertTrue(IpIntel::where('ip', '203.0.113.7')->exists());
        $this->assertFalse(IpIntel::where('ip', '198.51.100.9')->exists());
    }

    public function test_open_alerts_are_never_pruned(): void
    {
        $open = Alert::create([
            'rule' => 'web_scan', 'severity' => 3, 'title' => 'x', 'src_ip' => '203.0.113.6',
            'host' => 'web1', 'first_seen_at' => now()->subDays(400), 'last_seen_at' => now()->subDays(400),
            'event_count' => 1, 'status' => 'open',
        ]);

        $this->artisan('bawls:prune')->assertSuccessful();

        $this->assertModelExists($open);
    }
}
