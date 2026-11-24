<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Tests\TestCase;

class DashboardTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // The console is behind auth; these tests exercise its data, not its gate.
        $this->signIn();
    }

    public function test_the_overview_renders(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('Bawls', false);
    }

    public function test_an_open_alert_says_whether_its_address_is_banned_right_now(): void
    {
        $this->fakeBans(['203.0.113.9' => ['2026-11-18 07:54:00', '2026-11-25 07:54:00']]);
        foreach (['203.0.113.9', '198.51.100.4'] as $ip) {
            Alert::factory()->create(['title' => "Exploit from {$ip}", 'src_ip' => $ip]);
        }

        $alerts = collect($this->get('/')->viewData('page')['props']['openAlerts'])->pluck('banned', 'src_ip');

        $this->assertTrue($alerts['203.0.113.9']);
        $this->assertFalse($alerts['198.51.100.4']);
    }

    public function test_top_probed_paths_leave_out_flood_summaries(): void
    {
        $sensor = Sensor::factory()->create();
        $hit = fn (array $raw): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'occurred_at' => now()->subMinutes(5),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => '203.0.113.5', 'raw' => $raw,
        ]);

        $hit(['path' => '/.env', 'signature' => 'dirbust']);
        $hit(['path' => '/.env', 'signature' => 'dirbust']);
        $hit(['path' => '/', 'signature' => 'benign']);
        foreach (range(1, 3) as $i) {
            $hit(['path' => '(suppressed flood)', 'signature' => 'flood', 'suppressed' => 50]);
        }

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertSame(
            [['path' => '/.env', 'hits' => 2], ['path' => '/', 'hits' => 1]],
            $props['aggregates']['paths'],
        );
        // Still visible where it means something: the signature mix.
        $this->assertContains(['signature' => 'flood', 'hits' => 3], $props['aggregates']['signatures']);
    }

    public function test_the_weekly_digest_lists_probes_the_signatures_missed(): void
    {
        $sensor = Sensor::factory()->create();
        $hit = fn (string $ip, array $raw, ?Carbon $at = null): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'occurred_at' => $at ?? now()->subHours(2),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => $ip,
            'raw' => $raw + ['method' => 'GET', 'status' => 200, 'query' => '', 'signature' => 'benign'],
        ]);

        // Missed: an unknown path (404), query strings on a real page, a POST.
        $hit('203.0.113.1', ['path' => '/developmentserver/metadatauploader', 'status' => 404]);
        $hit('203.0.113.2', ['path' => '/developmentserver/metadatauploader', 'status' => 404, 'signature' => 'scanner_ua']);
        $hit('203.0.113.3', ['path' => '/', 'query' => 'url=.env']);
        $hit('203.0.113.4', ['path' => '/', 'query' => 'url=.env']);
        $hit('203.0.113.4', ['path' => '/', 'query' => 'XDEBUG_SESSION_START=phpstorm']);
        $hit('203.0.113.5', ['path' => '/', 'method' => 'POST', 'query' => 'rest_route=/batch/v1']);

        // Not missed: page views (a flaky 503 and a HEAD too), labelled attacks,
        // and anything older than a week.
        $hit('203.0.113.6', ['path' => '/pricing']);
        $hit('203.0.113.6', ['path' => '/investors', 'status' => 503]);
        $hit('203.0.113.6', ['path' => '/', 'method' => 'HEAD']);
        $hit('203.0.113.7', ['path' => '/.env', 'signature' => 'dirbust', 'query' => 'x=1']);
        $hit('203.0.113.8', ['path' => '/', 'signature' => 'sqli', 'query' => "id=1' or 1=1"]);
        $hit('203.0.113.9', ['path' => '/old-probe', 'status' => 404], now()->subDays(8));

        $digest = $this->get('/')->viewData('page')['props']['unrecognised'];

        $this->assertSame(7, $digest['days']);
        $this->assertSame(6, $digest['hits']);
        $this->assertSame(5, $digest['sources']);

        // Ranked by addresses, then requests.
        $rows = array_map(fn (array $r): array => array_diff_key($r, ['last_seen' => 0, 'explain' => 0, 'filter' => 0]), $digest['rows']);
        $this->assertSame([
            ['method' => 'GET', 'path' => '/', 'hits' => 3, 'sources' => 2, 'query' => 'url=.env', 'queries' => 2],
            ['method' => 'GET', 'path' => '/developmentserver/metadatauploader', 'hits' => 2, 'sources' => 2, 'query' => null, 'queries' => 0],
            ['method' => 'POST', 'path' => '/', 'hits' => 1, 'sources' => 1, 'query' => 'rest_route=/batch/v1', 'queries' => 1],
        ], $rows);
        $this->assertSame('2 hours ago', $digest['rows'][0]['last_seen']);
    }

    public function test_clicking_a_digest_row_filters_the_stream_to_exactly_its_requests(): void
    {
        $sensor = Sensor::factory()->create();
        $hit = fn (array $raw): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'occurred_at' => now()->subHour(),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => '203.0.113.20',
            'raw' => $raw + ['method' => 'GET', 'status' => 200, 'query' => '', 'signature' => 'benign'],
        ]);
        $hit(['path' => '/', 'query' => 'url=.env']);
        $hit(['path' => '/', 'query' => 'XDEBUG_SESSION_START=phpstorm']);
        $hit(['path' => '/', 'method' => 'POST', 'query' => 'rest_route=/batch/v1']);
        $hit(['path' => '/']);                                          // a plain visit
        $hit(['path' => '/', 'signature' => 'sqli', 'query' => 'id=1']); // labelled already

        // Each row carries its own filter (ProbeDigest::filter), and applying
        // it finds exactly the requests the row counted.
        $rows = $this->get('/')->viewData('page')['props']['unrecognised']['rows'];
        $matched = fn (string $filter): int => $this->get('/?f='.urlencode($filter))->viewData('page')['props']['stream']['matched'];
        $this->assertSame(['GET' => 2, 'POST' => 1], array_column($rows, 'hits', 'method'));
        foreach ($rows as $row) {
            $this->assertSame($row['hits'], $matched($row['filter']), $row['filter']);
        }
        $this->assertSame('site == decoy && path == / && method == POST && sig in {benign scanner_ua}', $rows[1]['filter']);
    }

    public function test_the_digest_is_left_out_of_live_refreshes(): void
    {
        $version = $this->get('/')->viewData('page')['version'];

        $partial = $this->get('/', [
            'X-Inertia' => 'true', 'X-Inertia-Version' => $version,
            'X-Inertia-Partial-Component' => 'Overview', 'X-Inertia-Partial-Data' => 'stats,topSources',
        ])->json('props');

        $this->assertArrayHasKey('stats', $partial);
        $this->assertArrayNotHasKey('unrecognised', $partial);
    }

    public function test_unlabelled_page_views_count_as_benign_in_one_row(): void
    {
        $sensor = Sensor::factory()->create();
        foreach ([['signature' => 'benign'], ['signature' => 'benign'], [], ['signature' => 'sqli']] as $raw) {
            Event::factory()->create([
                'sensor_id' => $sensor->id, 'occurred_at' => now()->subMinutes(5),
                'source' => 'honeypot_http', 'action' => 'probed', 'raw' => ['path' => '/'] + $raw,
            ]);
        }

        $signatures = $this->get('/')->viewData('page')['props']['aggregates']['signatures'];

        $this->assertSame([['signature' => 'benign', 'hits' => 3], ['signature' => 'sqli', 'hits' => 1]], $signatures);
    }

    public function test_top_countries_count_only_addresses_seen_in_the_window(): void
    {
        $sensor = Sensor::factory()->create();
        foreach (['203.0.113.1' => 'FR', '203.0.113.2' => 'FR', '203.0.113.3' => 'US', '203.0.113.4' => 'DE'] as $ip => $cc) {
            IpIntel::create(['ip' => $ip, 'is_private' => false, 'country' => $cc, 'checked_at' => now()]);
        }
        foreach (['203.0.113.1' => 1, '203.0.113.2' => 2, '203.0.113.3' => 3, '203.0.113.4' => 40] as $ip => $hoursAgo) {
            Event::factory()->create(['sensor_id' => $sensor->id, 'src_ip' => $ip, 'occurred_at' => now()->subHours($hoursAgo)]);
        }

        $countries = $this->get('/')->viewData('page')['props']['aggregates']['countries'];

        // DE was last seen 40h ago, outside the 24h window.
        $this->assertSame([['country' => 'FR', 'n' => 2], ['country' => 'US', 'n' => 1]], $countries);
    }

    public function test_the_traffic_chart_total_matches_the_24h_stat(): void
    {
        // Regression: the tile counted a rolling 24h while the chart bucketed
        // from an hour boundary, so the two numbers disagreed on screen.
        $sensor = Sensor::factory()->create();

        foreach ([0, 1, 5, 12, 22] as $hoursAgo) {
            Event::factory()->count(3)->create([
                'sensor_id' => $sensor->id,
                'occurred_at' => now()->subHours($hoursAgo)->subMinutes(5),
            ]);
        }

        $page = $this->get('/')->viewData('page');
        $props = $page['props'];

        $chartTotal = collect($props['traffic'])->sum('count');

        $this->assertSame($props['stats']['events_24h'], $chartTotal);
    }

    public function test_the_chart_always_returns_24_zero_filled_buckets(): void
    {
        $this->get('/')->viewData('page');

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertCount(24, $props['traffic']);
        $this->assertSame(0, collect($props['traffic'])->sum('count'));
    }

    public function test_events_outside_the_window_are_excluded(): void
    {
        $sensor = Sensor::factory()->create();
        Event::factory()->count(4)->create([
            'sensor_id' => $sensor->id,
            'occurred_at' => now()->subDays(3),
        ]);

        $props = $this->get('/')->viewData('page')['props'];

        $this->assertSame(0, $props['stats']['events_24h']);
        $this->assertSame(4, $props['stats']['events_total']);
    }
}
