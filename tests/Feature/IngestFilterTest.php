<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

class IngestFilterTest extends TestCase
{
    use RefreshDatabase;

    private const TOKEN = 'filter-token-000000000000000000000000000000';

    protected function setUp(): void
    {
        parent::setUp();
        Sensor::factory()->withToken(self::TOKEN)->create();
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function event(array $overrides = []): array
    {
        return array_merge([
            'occurred_at' => '2026-09-08T02:00:00Z',
            'source' => 'ufw_block',
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => '203.0.113.9',
            'dst_ip' => '192.168.0.101',
            'dst_port' => 22,
            'action' => 'blocked',
        ], $overrides);
    }

    /**
     * @param  array<int, array<string, mixed>>  $events
     */
    private function send(array $events): TestResponse
    {
        return $this->withToken(self::TOKEN)->postJson('/api/ingest', ['events' => $events]);
    }

    public function test_it_drops_multicast_destinations(): void
    {
        // The router emits IGMP to 224.0.0.1 constantly — 91% of everything
        // this network produced before filtering.
        $this->send([$this->event(['proto' => 'igmp', 'dst_ip' => '224.0.0.1', 'dst_port' => null])])
            ->assertStatus(201)
            ->assertJson(['accepted' => 0, 'dropped' => 1]);

        $this->assertSame(0, Event::count());
    }

    public function test_it_drops_lan_to_lan_traffic(): void
    {
        $this->send([$this->event(['src_ip' => '192.168.0.80', 'dst_ip' => '192.168.0.101'])])
            ->assertStatus(201)
            ->assertJson(['accepted' => 0, 'dropped' => 1]);

        $this->assertSame(0, Event::count());
    }

    public function test_it_drops_a_host_talking_to_itself_over_its_lan_address(): void
    {
        $this->send([$this->event(['src_ip' => '192.168.0.101', 'dst_ip' => '192.168.0.101'])])
            ->assertStatus(201)
            ->assertJson(['accepted' => 0]);

        $this->assertSame(0, Event::count());
    }

    public function test_it_keeps_inbound_traffic_from_the_internet(): void
    {
        $this->send([$this->event(['src_ip' => '203.0.113.9', 'dst_ip' => '192.168.0.101'])])
            ->assertStatus(201)
            ->assertJson(['accepted' => 1, 'dropped' => 0]);

        $this->assertSame(1, Event::count());
    }

    public function test_it_keeps_outbound_traffic_to_the_internet(): void
    {
        $this->send([$this->event([
            'direction' => 'out',
            'source' => 'ebpf_connect',
            'action' => 'allowed',
            'src_ip' => '192.168.0.101',
            'dst_ip' => '140.82.114.6',
            'dst_port' => 443,
        ])])->assertJson(['accepted' => 1]);

        $this->assertSame(1, Event::count());
    }

    public function test_a_mixed_batch_keeps_only_the_external_events(): void
    {
        $this->send([
            $this->event(['dst_ip' => '224.0.0.1']),
            $this->event(['src_ip' => '192.168.0.80', 'dst_ip' => '192.168.0.101']),
            $this->event(['src_ip' => '198.51.100.7']),
        ])->assertJson(['accepted' => 1, 'dropped' => 2]);

        $this->assertSame('198.51.100.7', Event::sole()->src_ip);
    }

    public function test_a_fully_filtered_batch_still_marks_the_sensor_alive(): void
    {
        // A sensor seeing only noise must not look dead on the dashboard.
        $this->send([$this->event(['dst_ip' => '224.0.0.1'])])->assertStatus(201);

        $this->assertNotNull(Sensor::sole()->last_seen_at);
    }

    public function test_honeypot_hits_are_always_kept_even_lan_to_lan(): void
    {
        // A decoy hit from a LAN tester (both ends internal) would be dropped
        // by the internal filter for ordinary traffic, but honeypot_http hits
        // are always interesting.
        $this->send([$this->event([
            'source' => 'honeypot_http',
            'action' => 'probed',
            'proto' => 'tcp',
            'src_ip' => '192.168.0.42',
            'dst_ip' => '192.168.0.80',
            'dst_port' => 8088,
            'raw' => ['method' => 'GET', 'path' => '/.env', 'signature' => 'dirbust'],
        ])])->assertStatus(201)->assertJson(['accepted' => 1, 'dropped' => 0]);

        $event = Event::sole();
        $this->assertSame('honeypot_http', $event->source);
        $this->assertSame('/.env', $event->raw['path']);
    }

    public function test_filtering_can_be_turned_off(): void
    {
        config(['bawls.store.drop_internal' => false, 'bawls.store.drop_multicast' => false]);

        $this->send([
            $this->event(['dst_ip' => '224.0.0.1']),
            $this->event(['src_ip' => '192.168.0.80', 'dst_ip' => '192.168.0.101']),
        ])->assertJson(['accepted' => 2, 'dropped' => 0]);

        $this->assertSame(2, Event::count());
    }
}
