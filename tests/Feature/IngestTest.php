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
            'dst_ip' => '192.168.0.101',
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
}
