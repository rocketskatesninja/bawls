<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Services\Network;
use Database\Seeders\DemoSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Process;
use Tests\TestCase;

class DemoSeederTest extends TestCase
{
    use RefreshDatabase;

    /** RFC 5737's documentation ranges: never a real host. */
    private const DOCUMENTATION = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'];

    /**
     * Asks the sensor's own code what it would record for each request:
     * [signature, page served, status, login_attempt].
     */
    private const SENSOR_VERDICTS = <<<'PY'
        import json, sys, urllib.parse
        sys.path.insert(0, sys.argv[1])
        from decoy_sensor import DEFAULT_THEME_DIR, load_theme, resolve_route
        from signatures import classify, is_login_attempt

        theme = load_theme(DEFAULT_THEME_DIR)
        verdicts = []
        for r in json.load(sys.stdin):
            body = urllib.parse.urlencode(r["form"]) if r["form"] else r["body_excerpt"]
            status, page, _ = resolve_route(r["path"], theme, r["method"])
            signature = classify(r["method"], r["path"], r["query"], body, r["user_agent"], theme.pages, theme.logins)
            verdicts.append([signature, page, status, is_login_attempt(r["method"], r["path"], theme.logins)])
        json.dump(verdicts, sys.stdout)
        PY;

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

    public function test_its_decoy_requests_carry_what_the_sensor_would_record(): void
    {
        $this->seed(DemoSeeder::class);
        $requests = Event::where('source', 'honeypot_http')->get()->pluck('raw')->all();

        $sensor = Process::input(json_encode($requests))
            ->run(['python3', '-I', '-c', self::SENSOR_VERDICTS, base_path('sensors')])
            ->throw();
        $verdicts = json_decode($sensor->output(), true);

        $this->assertNotEmpty($requests);
        $mismatches = [];
        foreach ($requests as $i => $raw) {
            $seeded = [$raw['signature'], $raw['decoy'], $raw['status'], $raw['login_attempt'] ?? false];
            if ($seeded !== $verdicts[$i]) {
                $mismatches[] = "{$raw['method']} {$raw['path']}: seeded ".json_encode($seeded).', the sensor records '.json_encode($verdicts[$i]);
            }
        }
        $this->assertSame([], array_values(array_unique($mismatches)));
    }

    public function test_it_leaves_a_database_with_events_alone(): void
    {
        Event::factory()->create(['src_ip' => '8.8.8.8']);

        $this->seed(DemoSeeder::class);

        $this->assertSame(1, Event::count());
        $this->assertSame(0, Alert::count());
    }
}
