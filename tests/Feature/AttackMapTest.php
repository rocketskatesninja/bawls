<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** The overview's attack map: where the last 24 hours came from, and the worst of it. */
class AttackMapTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->actingAs(User::factory()->create());
        $this->sensor = Sensor::factory()->create();
    }

    private function located(string $ip, ?float $lat, ?float $lng, bool $private = false): void
    {
        IpIntel::create([
            'ip' => $ip, 'is_private' => $private, 'country' => 'NL', 'city' => 'Amsterdam',
            'latitude' => $lat, 'longitude' => $lng, 'checked_at' => now(),
        ]);
    }

    private function event(string $ip, ?string $signature = null, int $minutesAgo = 5): void
    {
        Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'src_ip' => $ip, 'occurred_at' => now()->subMinutes($minutesAgo),
            ...($signature === null
                ? ['source' => 'ufw_block', 'action' => 'blocked', 'raw' => null]
                : ['source' => 'honeypot_http', 'action' => 'probed', 'raw' => ['signature' => $signature]]),
        ]);
    }

    /** @return list<array<string, mixed>> */
    private function points(): array
    {
        return $this->get('/')->viewData('page')['props']['attackMap'];
    }

    public function test_addresses_in_one_place_share_a_point_coloured_by_the_worst_thing_they_did(): void
    {
        $this->located('203.0.113.1', 52.3702, 4.8952);
        $this->located('203.0.113.2', 52.3741, 4.8897);   // the same tenth of a degree
        $this->located('198.51.100.7', 1.3521, 103.8198);
        $this->event('203.0.113.1');
        $this->event('203.0.113.1');
        $this->event('203.0.113.2', 'sqli');
        $this->event('198.51.100.7', 'dirbust');

        $points = collect($this->points())->keyBy(fn (array $p): string => "{$p['lat']},{$p['lng']}");

        $this->assertCount(2, $points);
        $amsterdam = $points['52.4,4.9'];
        $this->assertSame(['addresses' => 2, 'events' => 3, 'kind' => 'exploit', 'country' => 'NL'], [
            'addresses' => $amsterdam['addresses'], 'events' => $amsterdam['events'], 'kind' => $amsterdam['kind'], 'country' => $amsterdam['country'],
        ]);
        $this->assertSame('scan', $points['1.4,103.8']['kind']);
    }

    public function test_it_leaves_out_private_unlocated_and_older_traffic(): void
    {
        $this->located('10.0.0.5', 52.37, 4.89, private: true);
        $this->located('203.0.113.3', null, null);
        $this->located('203.0.113.4', 40.71, -74.0);
        $this->event('10.0.0.5', 'sqli');
        $this->event('203.0.113.3', 'sqli');
        $this->event('203.0.113.4', 'sqli', minutesAgo: 60 * 30);
        $this->event('203.0.113.9', 'sqli');   // never enriched: no location

        $this->assertSame([], $this->points());
    }
}
