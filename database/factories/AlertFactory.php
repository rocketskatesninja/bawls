<?php

namespace Database\Factories;

use App\Models\Alert;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Alert>
 */
class AlertFactory extends Factory
{
    protected $model = Alert::class;

    /**
     * An open, critical exploit alert seen just now. Tests name what matters
     * to them: Alert::factory()->create(['src_ip' => ..., 'status' => 'acked']).
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'rule' => 'web_exploit',
            'severity' => 5,
            'title' => 'x',
            'src_ip' => fake()->ipv4(),
            'host' => 'web1',
            'first_seen_at' => now(),
            'last_seen_at' => now(),
            'event_count' => 1,
            'status' => 'open',
        ];
    }

    /** First and last seen this long ago. */
    public function seen(\DateTimeInterface $when): static
    {
        return $this->state(['first_seen_at' => $when, 'last_seen_at' => $when]);
    }
}
