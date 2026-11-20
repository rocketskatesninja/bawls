<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DashboardFilterTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->actingAs(User::factory()->create());
        $this->sensor = Sensor::factory()->create();

        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'direction' => 'in', 'action' => 'blocked',
            'src_ip' => '203.0.113.9', 'dst_ip' => '192.168.0.101', 'process' => null,
        ]);
        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'direction' => 'out', 'action' => 'allowed',
            'src_ip' => '192.168.0.101', 'dst_ip' => '140.82.114.6', 'process' => 'curl',
        ]);
        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'direction' => 'in', 'action' => 'accepted',
            'src_ip' => '198.51.100.4', 'dst_ip' => '192.168.0.101', 'process' => 'apache2',
        ]);
    }

    /**
     * @param  array<string, string>  $query
     * @return array<int, array<string, mixed>>
     */
    private function events(array $query = []): array
    {
        return $this->get('/?'.http_build_query($query))->viewData('page')['props']['recentEvents'];
    }

    public function test_it_returns_everything_by_default(): void
    {
        $this->assertCount(3, $this->events());
    }

    public function test_it_filters_by_direction(): void
    {
        $this->assertCount(2, $this->events(['direction' => 'in']));
        $this->assertCount(1, $this->events(['direction' => 'out']));
    }

    public function test_it_filters_by_action(): void
    {
        $this->assertCount(1, $this->events(['action' => 'blocked']));
        $this->assertCount(1, $this->events(['action' => 'accepted']));
    }

    public function test_it_searches_by_ip(): void
    {
        $events = $this->events(['q' => '203.0.113']);
        $this->assertCount(1, $events);
        $this->assertStringContainsString('203.0.113.9', $events[0]['src']);
    }

    public function test_it_searches_by_process(): void
    {
        $events = $this->events(['q' => 'curl']);
        $this->assertCount(1, $events);
        $this->assertSame('curl', $events[0]['process']);
    }

    public function test_filters_combine(): void
    {
        $this->assertCount(1, $this->events(['direction' => 'in', 'action' => 'accepted']));
        $this->assertCount(0, $this->events(['direction' => 'out', 'action' => 'blocked']));
    }

    public function test_the_stats_ignore_the_filters(): void
    {
        // The tiles are a fixed reference point; narrowing the list beneath
        // them must not silently change the totals above it.
        $props = $this->get('/?direction=out')->viewData('page')['props'];

        $this->assertSame(3, $props['stats']['events_24h']);
        $this->assertCount(1, $props['recentEvents']);
    }

    public function test_the_active_filters_come_back_to_the_page(): void
    {
        $props = $this->get('/?direction=in&q=curl')->viewData('page')['props'];

        $this->assertSame('in', $props['filters']['direction']);
        $this->assertSame('curl', $props['filters']['q']);
        $this->assertSame('all', $props['filters']['action']);
    }
}
