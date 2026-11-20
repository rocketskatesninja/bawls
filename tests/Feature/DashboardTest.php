<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DashboardTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // The console is behind auth; these tests exercise its data, not its gate.
        $this->actingAs(User::factory()->create());
    }

    public function test_the_overview_renders(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('Bawls', false);
    }

    public function test_top_probed_paths_leave_out_flood_summaries(): void
    {
        $sensor = Sensor::factory()->create();
        $hit = fn (array $raw): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'occurred_at' => now()->subMinutes(5),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => '203.0.113.5', 'raw' => $raw,
        ]);

        $hit(['path' => '/.env', 'signature' => 'dirbust']);
        $hit(['path' => '/.env', 'signature' => 'dirbust']);
        $hit(['path' => '/', 'signature' => 'benign']);
        foreach (range(1, 3) as $i) {
            $hit(['path' => '(suppressed flood)', 'signature' => 'flood', 'suppressed' => 50]);
        }

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertSame(
            [['path' => '/.env', 'hits' => 2], ['path' => '/', 'hits' => 1]],
            $props['aggregates']['paths'],
        );
        // Still visible where it means something: the signature mix.
        $this->assertContains(['signature' => 'flood', 'hits' => 3], $props['aggregates']['signatures']);
    }

    public function test_top_countries_count_only_addresses_seen_in_the_window(): void
    {
        $sensor = Sensor::factory()->create();
        foreach (['203.0.113.1' => 'FR', '203.0.113.2' => 'FR', '203.0.113.3' => 'US', '203.0.113.4' => 'DE'] as $ip => $cc) {
            IpIntel::create(['ip' => $ip, 'is_private' => false, 'country' => $cc, 'checked_at' => now()]);
        }
        foreach (['203.0.113.1' => 1, '203.0.113.2' => 2, '203.0.113.3' => 3, '203.0.113.4' => 40] as $ip => $hoursAgo) {
            Event::factory()->create(['sensor_id' => $sensor->id, 'src_ip' => $ip, 'occurred_at' => now()->subHours($hoursAgo)]);
        }

        $countries = $this->get('/')->viewData('page')['props']['aggregates']['countries'];

        // DE was last seen 40h ago, outside the 24h window.
        $this->assertSame([['country' => 'FR', 'n' => 2], ['country' => 'US', 'n' => 1]], $countries);
    }

    public function test_the_traffic_chart_total_matches_the_24h_stat(): void
    {
        // Regression: the tile counted a rolling 24h while the chart bucketed
        // from an hour boundary, so the two numbers disagreed on screen.
        $sensor = Sensor::factory()->create();

        foreach ([0, 1, 5, 12, 22] as $hoursAgo) {
            Event::factory()->count(3)->create([
                'sensor_id' => $sensor->id,
                'occurred_at' => now()->subHours($hoursAgo)->subMinutes(5),
            ]);
        }

        $page = $this->get('/')->viewData('page');
        $props = $page['props'];

        $chartTotal = collect($props['traffic'])->sum('count');

        $this->assertSame($props['stats']['events_24h'], $chartTotal);
    }

    public function test_the_chart_always_returns_24_zero_filled_buckets(): void
    {
        $this->get('/')->viewData('page');

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertCount(24, $props['traffic']);
        $this->assertSame(0, collect($props['traffic'])->sum('count'));
    }

    public function test_events_outside_the_window_are_excluded(): void
    {
        $sensor = Sensor::factory()->create();
        Event::factory()->count(4)->create([
            'sensor_id' => $sensor->id,
            'occurred_at' => now()->subDays(3),
        ]);

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertSame(0, $props['stats']['events_24h']);
        $this->assertSame(4, $props['stats']['events_total']);
    }
}
