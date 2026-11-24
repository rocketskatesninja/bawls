<?php

namespace Database\Factories;

use App\Models\Event;
use App\Models\Sensor;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Event>
 */
class EventFactory extends Factory
{
    protected $model = Event::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'occurred_at' => now(),
            'sensor_id' => Sensor::factory(),
            'host' => 'web1',
            'source' => 'ufw_block',
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => fake()->ipv4(),
            'src_port' => fake()->numberBetween(1024, 65535),
            'dst_ip' => '10.0.0.101',
            'dst_port' => fake()->numberBetween(1, 1024),
            'iface' => 'enp1s0',
            'action' => 'blocked',
        ];
    }

    /**
     * A request to the decoy, as the decoy sensor records one. $raw is merged
     * over an ordinary page view: ->decoy(['path' => '/.env', 'signature' => 'dirbust']).
     *
     * @param  array<string, mixed>  $raw
     */
    public function decoy(array $raw = []): static
    {
        return $this->state([
            'source' => 'honeypot_http',
            'action' => 'probed',
            'dst_port' => 8088,
            'iface' => null,
            'raw' => $raw + ['method' => 'GET', 'path' => '/', 'query' => '', 'signature' => 'benign', 'status' => 200],
        ]);
    }

    /**
     * An exploit attempt on one of the real sites, as the site-log sensor records one.
     *
     * @param  array<string, mixed>  $raw
     */
    public function site(string $site = 'example.com', array $raw = []): static
    {
        return $this->state([
            'source' => 'site_http',
            'action' => 'probed',
            'src_port' => null,
            'dst_port' => null,
            'iface' => null,
            'raw' => $raw + ['site' => $site, 'method' => 'GET', 'path' => '/', 'query' => '', 'signature' => 'sqli', 'status' => 404],
        ]);
    }
}
