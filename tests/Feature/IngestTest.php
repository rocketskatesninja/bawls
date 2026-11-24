<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class IngestTest extends TestCase
{
    use RefreshDatabase;

    private const TOKEN = 'test-token-000000000000000000000000000000000000';

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function validEvent(array $overrides = []): array
    {
        return array_merge([
            'occurred_at' => '2026-09-08T01:00:00Z',
            'source' => 'ufw_block',
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => '203.0.113.9',
            'src_port' => 54321,
            'dst_ip' => '10.0.0.101',
            'dst_port' => 22,
            'iface' => 'enp1s0',
            'action' => 'blocked',
        ], $overrides);
    }

    public function test_it_rejects_a_request_with_no_token(): void
    {
        $this->postJson('/api/ingest', ['events' => [$this->validEvent()]])
            ->assertStatus(401);

        $this->assertSame(0, Event::count());
    }

    public function test_it_rejects_an_unknown_token(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->create();

        $this->withToken('not-the-right-token')
            ->postJson('/api/ingest', ['events' => [$this->validEvent()]])
            ->assertStatus(401);

        $this->assertSame(0, Event::count());
    }

    public function test_it_rejects_a_disabled_sensor(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->disabled()->create();

        $this->withToken(self::TOKEN)
            ->postJson('/api/ingest', ['events' => [$this->validEvent()]])
            ->assertStatus(401);

        $this->assertSame(0, Event::count());
    }

    public function test_it_accepts_a_batch_and_stamps_it_with_the_sensor_host(): void
    {
        $sensor = Sensor::factory()->withToken(self::TOKEN)->create(['host' => 'web1']);

        $this->withToken(self::TOKEN)
            ->postJson('/api/ingest', ['events' => [
                $this->validEvent(),
                $this->validEvent(['src_ip' => '198.51.100.4', 'dst_port' => 80]),
            ]])
            ->assertStatus(201)
            ->assertJson(['accepted' => 2]);

        $this->assertSame(2, Event::count());

        $event = Event::where('src_ip', '203.0.113.9')->sole();
        $this->assertSame('web1', $event->host);
        $this->assertSame($sensor->id, $event->sensor_id);
        $this->assertSame(22, $event->dst_port);

        $sensor->refresh();
        $this->assertSame(2, (int) $sensor->events_received);
        $this->assertNotNull($sensor->last_seen_at);
    }

    public function test_it_rejects_a_malformed_event_without_persisting_the_batch(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->create();

        $this->withToken(self::TOKEN)
            ->postJson('/api/ingest', ['events' => [
                $this->validEvent(),
                $this->validEvent(['src_ip' => 'not-an-ip']),
            ]])
            ->assertStatus(422);

        $this->assertSame(0, Event::count());
    }

    public function test_it_rejects_an_unknown_source_type(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->create();

        $this->withToken(self::TOKEN)
            ->postJson('/api/ingest', ['events' => [$this->validEvent(['source' => 'made_up'])]])
            ->assertStatus(422);
    }

    public function test_it_rejects_a_batch_larger_than_the_cap(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->create();

        $this->withToken(self::TOKEN)
            ->postJson('/api/ingest', ['events' => array_fill(0, 501, $this->validEvent())])
            ->assertStatus(422);

        $this->assertSame(0, Event::count());
    }

    public function test_a_sensor_can_only_report_its_own_kind_of_event(): void
    {
        Sensor::factory()->decoy()->withToken(self::TOKEN)->create();

        // A decoy (or whoever holds its token) can't claim an exploit on a real site.
        $this->withToken(self::TOKEN)->postJson('/api/ingest', ['events' => [
            $this->validEvent(['source' => 'site_http', 'action' => 'probed', 'raw' => ['signature' => 'rce']]),
            $this->validEvent(['source' => 'honeypot_http', 'action' => 'probed', 'raw' => ['signature' => 'benign']]),
        ]])->assertStatus(201)->assertJson(['accepted' => 1, 'dropped' => 1]);

        $this->assertSame('honeypot_http', Event::sole()->source);
    }

    public function test_oversized_and_stale_events_are_dropped_and_future_ones_are_stamped_now(): void
    {
        Sensor::factory()->decoy()->withToken(self::TOKEN)->create();
        $event = fn (array $with): array => $this->validEvent(['source' => 'honeypot_http', 'action' => 'probed', ...$with]);

        $this->withToken(self::TOKEN)->postJson('/api/ingest', ['events' => [
            $event(['raw' => ['body_excerpt' => str_repeat('x', 70_000)]]),
            $event(['occurred_at' => now()->subYears(2)->toIso8601String()]),
            $event(['occurred_at' => now()->addYears(5)->toIso8601String()]),
        ]])->assertStatus(201)->assertJson(['accepted' => 1, 'dropped' => 2]);

        $this->assertTrue(Event::sole()->occurred_at->lte(now()->addMinutes(6)));
    }

    public function test_each_sensor_has_its_own_rate_limit(): void
    {
        Sensor::factory()->withToken(self::TOKEN)->create();
        Sensor::factory()->withToken('another-sensors-token')->create();
        $send = fn (string $token) => $this->withToken($token)->postJson('/api/ingest', ['events' => [$this->validEvent()]]);

        foreach (range(1, 120) as $n) {
            $send(self::TOKEN)->assertStatus(201);
        }
        $send(self::TOKEN)->assertStatus(429);
        $send('another-sensors-token')->assertStatus(201);
    }
}
