<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\Sensor;
use App\Models\User;
use App\Services\AlertDetector;
use App\Services\Crawler;
use App\Services\DisplayFilter;
use App\Services\IpEnricher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** Exploit attempts on your real sites (sensors/site_log_sensor.py), held to the decoy's rules. */
class SiteLogSensorTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    private string $log;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sensor = Sensor::factory()->create(['host' => 'web1']);
        $this->log = tempnam(sys_get_temp_dir(), 'bawls-ban-');
        config([
            'bawls.ban.enabled' => true,
            'bawls.ban.never_block' => '198.51.100.9',
            'bawls.ban.rules' => 'web_exploit',
            'bawls.ban.log' => $this->log,
            'bawls.ban.site' => true,
        ]);
    }

    protected function tearDown(): void
    {
        @unlink($this->log);
        Crawler::$dns = null;
        parent::tearDown();
    }

    private function siteHit(string $ip, string $site = 'example.com', string $signature = 'sqli', string $ago = '30 seconds', string $ua = 'sqlmap/1.8'): Event
    {
        return Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'host' => 'web1', 'occurred_at' => now()->sub($ago),
            'source' => 'site_http', 'action' => 'probed', 'proto' => 'tcp',
            'src_ip' => $ip, 'src_port' => null, 'dst_ip' => '192.0.2.10', 'dst_port' => null, 'iface' => null,
            'raw' => ['site' => $site, 'method' => 'GET', 'path' => '/index.php', 'query' => "id=1' OR 1=1--",
                'status' => 404, 'user_agent' => $ua, 'signature' => $signature],
        ]);
    }

    private function decoyHit(string $ip, string $ago = '30 seconds', string $ua = 'curl/8'): Event
    {
        return Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'host' => 'web1', 'occurred_at' => now()->sub($ago),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => $ip, 'dst_ip' => '192.0.2.10', 'dst_port' => 80,
            'raw' => ['method' => 'GET', 'path' => '/.env', 'user_agent' => $ua, 'signature' => 'cve_probe', 'status' => 200],
        ]);
    }

    /** @return list<string> the addresses written to the ban feed */
    private function banned(): array
    {
        preg_match_all('/ bawls ban (\S+) /', (string) file_get_contents($this->log), $m);

        return $m[1];
    }

    // ---- ingest ---------------------------------------------------------------

    public function test_ingest_takes_site_events_and_keeps_them_even_from_the_lan(): void
    {
        config(['bawls.store.drop_internal' => true]);
        Sensor::factory()->withToken('site-token')->create(['host' => 'web1', 'name' => 'web1-sites']);

        $this->withToken('site-token')->postJson('/api/ingest', ['events' => [[
            'occurred_at' => '2026-11-20T19:05:09+00:00', 'source' => 'site_http', 'direction' => 'in', 'proto' => 'tcp',
            'src_ip' => '10.0.0.50', 'src_port' => null, 'dst_ip' => '10.0.0.80', 'dst_port' => null, 'action' => 'probed',
            'raw' => ['site' => 'shop.example.com', 'method' => 'GET', 'path' => '/../../etc/passwd', 'signature' => 'traversal'],
        ]]])->assertStatus(201)->assertJson(['accepted' => 1]);

        $this->assertSame('shop.example.com', Event::sole()->raw['site']);
    }

    // ---- the rule: the decoy's, the same bans ---------------------------------

    public function test_a_real_site_exploit_raises_the_decoys_rule_and_bans_the_same_way(): void
    {
        $this->siteHit('203.0.113.9');
        $this->siteHit('203.0.113.9');

        app(AlertDetector::class)->run();

        $alert = Alert::sole();
        $this->assertSame('web_exploit', $alert->rule);
        $this->assertSame(5, $alert->severity);
        $this->assertSame('Exploit attempt: 2 on example.com from 203.0.113.9', $alert->title);
        $this->assertSame(['attempts' => 2, 'on_decoy' => 0, 'on_sites' => ['example.com']], $alert->details);
        $this->assertSame(['203.0.113.9'], $this->banned());
    }

    public function test_one_attacker_on_the_decoy_and_two_sites_is_one_alert_that_says_where(): void
    {
        $this->decoyHit('203.0.113.9');
        $this->siteHit('203.0.113.9', 'shop.example.com');
        $this->siteHit('203.0.113.9', 'example.com');

        app(AlertDetector::class)->run();

        $this->assertSame('Exploit attempt: 3 on the decoy, example.com and shop.example.com from 203.0.113.9', Alert::sole()->title);
    }

    public function test_scans_on_a_real_site_never_count(): void
    {
        $this->siteHit('203.0.113.9', signature: 'dirbust');

        app(AlertDetector::class)->run();

        $this->assertSame(0, Alert::count());
        $this->assertSame([], $this->banned());
    }

    public function test_never_block_addresses_are_recorded_but_never_banned(): void
    {
        $this->siteHit('198.51.100.9');

        app(AlertDetector::class)->run();

        $this->assertSame(1, Alert::count());
        $this->assertSame([], $this->banned());
    }

    // ---- the watch period ------------------------------------------------------

    public function test_while_watching_a_real_site_exploit_alerts_but_does_not_ban(): void
    {
        config(['bawls.ban.site' => false]);
        $this->siteHit('203.0.113.9');

        app(AlertDetector::class)->run();

        $this->assertSame(1, Alert::count());
        $this->assertSame([], $this->banned());
    }

    public function test_while_watching_the_decoy_still_bans_even_on_the_same_alert(): void
    {
        config(['bawls.ban.site' => false]);
        $this->siteHit('203.0.113.9', ago: '3 minutes');
        app(AlertDetector::class)->run();
        $this->assertSame([], $this->banned());

        $this->decoyHit('203.0.113.9');
        app(AlertDetector::class)->run();

        $this->assertSame(['203.0.113.9'], $this->banned());
        $this->assertSame(1, Alert::count());
    }

    public function test_while_watching_new_real_site_activity_on_an_alert_does_not_ban(): void
    {
        config(['bawls.ban.site' => false]);
        $this->decoyHit('203.0.113.9', ago: '5 minutes');
        app(AlertDetector::class)->run();
        $this->assertCount(1, $this->banned());

        $this->siteHit('203.0.113.9');
        app(AlertDetector::class)->run();

        $this->assertCount(1, $this->banned(), 'only the decoy hit banned');
    }

    // ---- crawlers ---------------------------------------------------------------

    public function test_a_genuine_search_crawler_is_recorded_but_never_banned(): void
    {
        $lookups = 0;
        Crawler::$dns = function (string $ip) use (&$lookups): array {
            $lookups++;

            return ['crawl-66-249-66-1.googlebot.com.', [$ip]];
        };
        $this->siteHit('66.249.66.1', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        app(AlertDetector::class)->run();

        $this->assertSame(1, Alert::count());
        $this->assertSame([], $this->banned());
        $this->assertSame(1, $lookups);
    }

    public function test_the_decoy_spares_genuine_crawlers_too(): void
    {
        Crawler::$dns = fn (string $ip): array => ['msnbot-157-55-39-1.search.msn.com', [$ip]];
        $this->decoyHit('157.55.39.1', ua: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)');

        app(AlertDetector::class)->run();

        $this->assertSame([], $this->banned());
    }

    public function test_a_crawler_impostor_is_banned(): void
    {
        Crawler::$dns = fn (string $ip): array => ['host-203-0-113-9.example.net', [$ip]];   // not Google's
        $this->siteHit('203.0.113.9', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)');

        app(AlertDetector::class)->run();

        $this->assertSame(['203.0.113.9'], $this->banned());
    }

    public function test_a_name_in_the_right_domain_must_also_resolve_back(): void
    {
        // Anyone can set their own reverse DNS to look like Google's; the
        // forward lookup of that name is what proves it.
        Crawler::$dns = fn (string $ip): array => ['crawl.googlebot.com', ['66.249.66.1']];
        $this->siteHit('203.0.113.9', ua: 'Googlebot/2.1');

        app(AlertDetector::class)->run();

        $this->assertSame(['203.0.113.9'], $this->banned());
    }

    public function test_no_crawler_claim_means_no_dns_lookup(): void
    {
        Crawler::$dns = fn (): array => throw new \LogicException('looked up an address that claimed nothing');
        $this->siteHit('203.0.113.9');

        app(AlertDetector::class)->run();

        $this->assertSame(['203.0.113.9'], $this->banned());
    }

    // ---- the console ------------------------------------------------------------

    public function test_the_stream_shows_a_site_hit_as_an_http_exploit_naming_the_site(): void
    {
        $this->siteHit('203.0.113.9');

        $row = $this->actingAs(User::factory()->create())->get('/')->viewData('page')['props']['stream']['rows'][0];

        $this->assertSame(['exploit', 'HTTP', "GET /index.php?id=1' OR 1=1-- · sqli → 404 · example.com"], [$row['kind'], $row['proto'], $row['info']]);
    }

    public function test_the_filter_tells_sites_and_the_decoy_apart(): void
    {
        $site = $this->siteHit('203.0.113.9')->id;
        $decoy = $this->decoyHit('203.0.113.10')->id;
        $ufw = Event::factory()->create(['sensor_id' => $this->sensor->id])->id;
        $ids = fn (string $filter): array => DisplayFilter::parse($filter)->apply(Event::query(), 'UTC')->orderBy('id')->pluck('id')->all();

        $this->assertSame([$site], $ids('site == example.com'));
        $this->assertSame([$decoy], $ids('site == decoy'));
        $this->assertSame([$site], $ids('site != decoy'), 'firewall events have no site');
        $this->assertSame([$decoy], $ids('decoy'));
        $this->assertSame([$site, $decoy], $ids('http'));
        $this->assertSame([$site], $ids('sig == sqli'));
        $this->assertSame([$ufw], $ids('ufw'));
    }

    public function test_the_details_pane_names_the_site_and_offers_its_filter(): void
    {
        $event = $this->siteHit('203.0.113.9');

        $http = collect($this->actingAs(User::factory()->create())->getJson("/events/{$event->id}")->json('sections'))
            ->firstWhere('title', 'HTTP')['fields'];

        $this->assertSame(['label' => 'Site', 'value' => 'example.com', 'filter' => 'site == example.com'], $http[0]);
        $this->assertContains(['label' => 'Site answered', 'value' => '404', 'filter' => 'status == 404'],
            collect($this->actingAs(User::factory()->create())->getJson("/events/{$event->id}")->json('sections'))->firstWhere('title', 'Detection')['fields']);
    }

    public function test_site_attackers_are_enriched_like_decoy_ones(): void
    {
        config(['bawls.enrich.per_run' => 10]);
        $this->siteHit('203.0.113.9');
        $enriched = [];
        $this->mock(IpEnricher::class, function ($mock) use (&$enriched): void {
            $mock->shouldReceive('enrich')->andReturnUsing(function (string $ip) use (&$enriched) {
                $enriched[] = $ip;

                return null;
            });
        });

        $this->artisan('bawls:enrich')->assertSuccessful();

        $this->assertSame(['203.0.113.9'], $enriched);
    }
}
