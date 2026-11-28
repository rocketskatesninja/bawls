<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** The stream's kinds, worked out in PHP (kind()) and in SQL (kindSql()), agree. */
class EventKindTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_sql_kind_matches_the_php_kind_for_every_shape_of_event(): void
    {
        $sensor = Sensor::factory()->create();
        $make = fn (string $source, string $action, ?array $raw): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'source' => $source, 'action' => $action, 'raw' => $raw,
        ]);
        $events = [
            'firewall' => $make('ufw_block', 'blocked', null),
            'other' => $make('ufw_block', 'allowed', null),
            'page' => $make('honeypot_http', 'probed', ['signature' => 'benign']),
            'no signature' => $make('honeypot_http', 'probed', ['path' => '/']),
            'browser check' => $make('honeypot_http', 'probed', ['signature' => 'browser_check']),
            'login' => $make('honeypot_http', 'probed', ['signature' => 'login', 'login_attempt' => true]),
            'login, unlabelled' => $make('honeypot_http', 'probed', ['signature' => 'benign', 'login_attempt' => true]),
            'login carrying an exploit' => $make('honeypot_http', 'probed', ['signature' => 'sqli', 'login_attempt' => true]),
            'dirbust' => $make('honeypot_http', 'probed', ['signature' => 'dirbust']),
            'scanner' => $make('honeypot_http', 'probed', ['signature' => 'scanner_ua']),
            'flood' => $make('honeypot_http', 'probed', ['signature' => 'flood']),
            'exploit on a real site' => $make('site_http', 'probed', ['signature' => 'cve_probe', 'site' => 'example.com']),
        ];

        $sql = DB::table('events')->selectRaw('id, '.Event::kindSql().' AS kind')->pluck('kind', 'id');

        foreach ($events as $what => $event) {
            $this->assertSame($event->kind(), $sql[$event->id], $what);
        }
        $this->assertEqualsCanonicalizing(Event::KINDS, array_values(array_unique(array_map(fn (Event $e): string => $e->kind(), $events))), 'the fixtures cover every kind');
    }

    public function test_each_chart_bar_says_what_its_hour_was_made_of(): void
    {
        $sensor = Sensor::factory()->create();
        Event::factory()->count(3)->create(['sensor_id' => $sensor->id, 'occurred_at' => now()]);
        Event::factory()->create([
            'sensor_id' => $sensor->id, 'occurred_at' => now(), 'source' => 'honeypot_http', 'action' => 'probed',
            'raw' => ['signature' => 'rce'],
        ]);

        $traffic = $this->signIn()->get('/')->viewData('page')['props']['traffic'];
        $now = end($traffic);

        $this->assertSame(4, $now['count']);
        $this->assertSame(['exploit' => 1, 'login' => 0, 'scan' => 0, 'page' => 0, 'firewall' => 3, 'other' => 0], $now['kinds']);
        foreach ($traffic as $bar) {
            $this->assertSame($bar['count'], array_sum($bar['kinds']));
        }
    }
}
