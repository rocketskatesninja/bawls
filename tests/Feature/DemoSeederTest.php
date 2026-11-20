<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Services\Network;
use Database\Seeders\DemoSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DemoSeederTest extends TestCase
{
    use RefreshDatabase;

    /** RFC 5737's documentation ranges: never a real host. */
    private const DOCUMENTATION = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'];

    public function test_it_fills_an_empty_database_with_fictional_addresses_only(): void
    {
        $log = storage_path('framework/testing/demo-ban.log');
        @unlink($log);
        config(['bawls.ban.enabled' => true, 'bawls.ban.log' => $log]);

        $this->seed(DemoSeeder::class);

        $this->assertGreaterThan(500, Event::count());
        $this->assertGreaterThanOrEqual(5, Alert::count());
        $this->assertTrue(Alert::where('rule', 'web_exploit')->exists());

        $addresses = Event::distinct()->pluck('src_ip')
            ->merge(Event::distinct()->pluck('dst_ip'))
            ->merge(IpIntel::pluck('ip'))
            ->unique();
        foreach ($addresses as $ip) {
            $this->assertTrue(Network::inAny($ip, self::DOCUMENTATION), "$ip is outside the documentation ranges");
        }

        // Fictional attackers must never reach a real firewall.
        $this->assertFileDoesNotExist($log);
    }

    public function test_it_leaves_a_database_with_events_alone(): void
    {
        Event::factory()->create(['src_ip' => '8.8.8.8']);

        $this->seed(DemoSeeder::class);

        $this->assertSame(1, Event::count());
        $this->assertSame(0, Alert::count());
    }
}
