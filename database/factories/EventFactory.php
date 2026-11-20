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
            'dst_ip' => '192.168.0.101',
            'dst_port' => fake()->numberBetween(1, 1024),
            'iface' => 'enp1s0',
            'action' => 'blocked',
        ];
    }
}
