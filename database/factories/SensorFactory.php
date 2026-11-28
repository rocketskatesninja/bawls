<?php

namespace Database\Factories;

use App\Models\Sensor;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Sensor>
 */
class SensorFactory extends Factory
{
    protected $model = Sensor::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'name' => fake()->unique()->slug(2),
            'host' => fake()->randomElement(['web1', 'web2', 'db1']),
            'kind' => 'ufw',
            'token_hash' => hash('sha256', fake()->regexify('[A-Za-z0-9]{48}')),
            'enabled' => true,
        ];
    }

    /** The decoy: reports honeypot_http events. */
    public function decoy(): static
    {
        return $this->state(['kind' => 'honeypot']);
    }

    /** The real-site log sensor: reports site_http events. */
    public function sites(): static
    {
        return $this->state(['kind' => 'sites']);
    }

    /**
     * Issue the sensor a known plaintext token so a test can authenticate as it.
     */
    public function withToken(string $token): static
    {
        return $this->state(fn (): array => ['token_hash' => hash('sha256', $token)]);
    }

    public function disabled(): static
    {
        return $this->state(fn (): array => ['enabled' => false]);
    }
}
