<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use App\Models\User;
use App\Services\Settings;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Tests\TestCase;

/** The overview's event stream under its display filter. */
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
            'src_ip' => '203.0.113.9', 'dst_ip' => '10.0.0.101', 'process' => null,
        ]);
        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'direction' => 'out', 'action' => 'allowed',
            'src_ip' => '10.0.0.101', 'dst_ip' => '140.82.114.6', 'process' => 'curl',
        ]);
        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'direction' => 'in', 'action' => 'accepted',
            'src_ip' => '198.51.100.4', 'dst_ip' => '10.0.0.101', 'process' => 'apache2',
        ]);
    }

    /**
     * @param  array<string, string|int>  $query
     * @return array<string, mixed>
     */
    private function stream(array $query = []): array
    {
        return $this->get('/?'.http_build_query($query))->viewData('page')['props']['stream'];
    }

    public function test_it_returns_everything_by_default(): void
    {
        $stream = $this->stream();

        $this->assertCount(3, $stream['rows']);
        $this->assertSame(3, $stream['matched']);
        $this->assertNull($stream['error']);
    }

    public function test_rows_from_before_today_carry_their_date_in_the_display_zone(): void
    {
        app(Settings::class)->update(['timezone' => 'America/New_York']);
        Carbon::setTestNow('2026-11-23 15:00:00');   // 10:00 in New York
        $today = Event::factory()->create(['sensor_id' => $this->sensor->id, 'src_ip' => '192.0.2.1', 'occurred_at' => '2026-11-23 14:30:05']);
        // Still Nov 23 in UTC, but 22:00 on Nov 22 in New York.
        $yesterday = Event::factory()->create(['sensor_id' => $this->sensor->id, 'src_ip' => '192.0.2.2', 'occurred_at' => '2026-11-23 03:00:00']);

        $at = collect($this->stream(['f' => 'src in {192.0.2.1 192.0.2.2}'])['rows'])->pluck('at', 'id');

        $this->assertSame('09:30:05', $at[$today->id]);
        $this->assertSame('Nov 22 22:00:00', $at[$yesterday->id]);
        Carbon::setTestNow();
    }

    public function test_the_filter_narrows_the_stream_and_comes_back_to_the_page(): void
    {
        $stream = $this->stream(['f' => 'dir == in && (process == apache2 || src == 203.0.113.9)']);

        $this->assertSame(['198.51.100.4', '203.0.113.9'], collect($stream['rows'])->pluck('src_ip')->sort()->values()->all());
        $this->assertSame(2, $stream['matched']);
        $this->assertSame('dir == in && (process == apache2 || src == 203.0.113.9)', $stream['filter']);
    }

    public function test_a_broken_filter_comes_back_as_an_error_not_an_exception(): void
    {
        $stream = $this->stream(['f' => 'src = 203.0.113.9']);

        $this->assertSame([], $stream['rows']);
        $this->assertSame(['message' => 'Compare with ==, not =.', 'at' => 4], $stream['error']);
    }

    public function test_the_stats_ignore_the_filter(): void
    {
        $props = $this->get('/?f='.urlencode('dir == out'))->viewData('page')['props'];

        $this->assertSame(3, $props['stats']['events_total']);
        $this->assertCount(1, $props['stream']['rows']);
    }

    public function test_the_stream_shows_200_rows_and_load_older_adds_200_up_to_1000(): void
    {
        Event::factory()->count(250)->create(['sensor_id' => $this->sensor->id]);

        $this->assertCount(200, $this->stream()['rows']);
        $this->assertSame(253, $this->stream()['matched']);
        $this->assertCount(253, $this->stream(['limit' => 400])['rows']);
        $this->assertSame(1000, $this->stream(['limit' => 999999])['limit']);
        $this->assertSame(200, $this->stream(['limit' => -5])['limit']);
    }

    public function test_the_filter_bar_can_check_a_filter_as_you_type(): void
    {
        $this->getJson('/stream/check?f='.urlencode('src == 203.0.113.9'))
            ->assertOk()->assertExactJson(['ok' => true, 'error' => null]);
        $this->getJson('/stream/check?f='.urlencode('src ='))
            ->assertOk()->assertJson(['ok' => false, 'error' => ['at' => 4]]);
    }

    public function test_signed_out_visitors_get_a_404_from_the_check(): void
    {
        auth()->logout();

        $this->get('/stream/check?f=ufw')->assertNotFound();
    }

    public function test_the_chart_covers_24_hours_or_7_days(): void
    {
        $this->travelTo('2026-11-20 14:35:00');
        Event::factory()->create(['sensor_id' => $this->sensor->id, 'occurred_at' => '2026-11-14 09:10:00']);

        $day = $this->get('/')->viewData('page')['props'];
        $week = $this->get('/?range=7d')->viewData('page')['props'];

        $this->assertSame('24h', $day['range']);
        $this->assertCount(24, $day['traffic']);
        $this->assertSame('7d', $week['range']);
        $this->assertCount(168, $week['traffic']);
        $this->assertSame('Fri 14:00', $week['traffic'][167]['hour'], 'a week of bars names the day');
        $this->assertSame(1, collect($week['traffic'])->firstWhere('from', '2026-11-14 09:00')['count']);
        $this->assertSame('24h', $this->get('/?range=forever')->viewData('page')['props']['range']);
    }

    public function test_each_chart_bar_carries_its_hour_for_the_filter(): void
    {
        $this->travelTo('2026-11-20 14:35:00');

        $last = collect($this->get('/')->viewData('page')['props']['traffic'])->last();

        $this->assertSame(['hour' => '14:00', 'from' => '2026-11-20 14:00', 'to' => '2026-11-20 15:00'], [
            'hour' => $last['hour'], 'from' => $last['from'], 'to' => $last['to'],
        ]);
    }
}
