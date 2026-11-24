<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\Sensor;
use App\Services\AlertDetector;
use App\Services\Blocklist;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class BanFeedTest extends TestCase
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
            'bawls.ban.never_block' => '198.51.100.9, 203.0.113.128/25',
            'bawls.ban.rules' => 'web_exploit',
            'bawls.ban.log' => $this->log,
        ]);
    }

    protected function tearDown(): void
    {
        @unlink($this->log);

        parent::tearDown();
    }

    /**
     * Decoy hits from one source, each with the given signature.
     */
    private function hits(string $ip, int $count, string $signature, string $ago = '30 seconds'): void
    {
        for ($i = 0; $i < $count; $i++) {
            Event::factory()->decoy(['path' => '/p'.$i, 'signature' => $signature])->create([
                'sensor_id' => $this->sensor->id, 'occurred_at' => now()->sub($ago), 'src_ip' => $ip,
            ]);
        }
    }

    /**
     * @return array<int, string>
     */
    private function lines(): array
    {
        return array_values(array_filter(explode("\n", (string) file_get_contents($this->log))));
    }

    private function alert(string $ip, string $rule = 'web_exploit'): Alert
    {
        return Alert::factory()->create(['rule' => $rule, 'src_ip' => $ip]);
    }

    public function test_a_new_exploit_alert_writes_one_ban_line(): void
    {
        $this->hits('203.0.113.7', 3, 'sqli');

        (new AlertDetector)->run();

        $alert = Alert::where('rule', 'web_exploit')->sole();
        $lines = $this->lines();
        $this->assertCount(1, $lines);
        $this->assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z bawls ban 203\.0\.113\.7 rule=web_exploit alert='.$alert->id.'$/',
            $lines[0],
        );
    }

    public function test_a_rerun_without_new_activity_writes_nothing_more(): void
    {
        $this->hits('203.0.113.7', 3, 'sqli');

        (new AlertDetector)->run();
        (new AlertDetector)->run();

        $this->assertCount(1, $this->lines());
    }

    public function test_new_activity_on_an_open_alert_requests_the_ban_again(): void
    {
        $this->hits('203.0.113.7', 3, 'sqli', '2 minutes');
        (new AlertDetector)->run();

        $this->hits('203.0.113.7', 1, 'rce', '10 seconds');
        (new AlertDetector)->run();

        $this->assertSame(1, Alert::where('rule', 'web_exploit')->count());
        $this->assertCount(2, $this->lines());
    }

    public function test_never_block_ips_alert_but_are_not_banned(): void
    {
        $this->hits('198.51.100.9', 3, 'sqli');   // exact never-block entry
        $this->hits('203.0.113.200', 3, 'sqli');  // inside a never-block CIDR

        (new AlertDetector)->run();

        $this->assertSame(1, Alert::where('src_ip', '198.51.100.9')->count());
        $this->assertSame([], $this->lines());
    }

    public function test_internal_ips_are_not_banned(): void
    {
        $this->hits('10.0.0.50', 3, 'sqli');

        (new AlertDetector)->run();

        $this->assertSame([], $this->lines());
    }

    public function test_rules_outside_the_ban_list_are_not_banned(): void
    {
        // 12 distinct paths trips web_scan; dirbust isn't an exploit signature.
        $this->hits('203.0.113.8', 12, 'dirbust');

        (new AlertDetector)->run();

        $this->assertSame(1, Alert::where('rule', 'web_scan')->count());
        $this->assertSame([], $this->lines());
    }

    public function test_nothing_is_written_when_the_feed_is_disabled(): void
    {
        config(['bawls.ban.enabled' => false]);
        $this->hits('203.0.113.7', 3, 'sqli');

        (new AlertDetector)->run();

        $this->assertSame(1, Alert::where('rule', 'web_exploit')->count());
        $this->assertSame([], $this->lines());
    }

    public function test_the_blocklist_leaves_out_never_block_and_internal_ips(): void
    {
        $this->alert('203.0.113.9');    // outside → listed
        $this->alert('198.51.100.9');   // never-block entry
        $this->alert('203.0.113.200');  // inside a never-block CIDR
        $this->alert('10.0.0.5');    // private

        $this->assertSame(['203.0.113.9'], Blocklist::ips()->all());
    }

    public function test_a_never_block_cidr_covers_public_addresses_inside_it(): void
    {
        config(['bawls.ban.never_block' => '192.0.2.0/24']);

        $this->assertFalse(Blocklist::eligible('192.0.2.170'));
        $this->assertTrue(Blocklist::eligible('192.0.3.1'));
    }

    public function test_config_lists_tolerate_spaces_and_empty_entries(): void
    {
        config([
            'bawls.ban.never_block' => ' , 198.51.100.9 ,, ',
            'bawls.ban.rules' => ' web_scan , web_exploit ,',
        ]);

        $this->assertFalse(Blocklist::eligible('198.51.100.9'));

        Blocklist::ban($this->alert('203.0.113.20', 'web_scan'));
        $this->assertCount(1, $this->lines());
    }

    public function test_a_request_sent_from_another_sites_page_alerts_but_never_bans(): void
    {
        // An innocent visitor to a page that embeds <img src="https://us/?q=../">.
        Event::factory()->decoy(['query' => 'q=../', 'signature' => 'traversal', 'cross_site' => true])->create([
            'sensor_id' => $this->sensor->id, 'occurred_at' => now()->subSeconds(30), 'src_ip' => '203.0.113.40',
        ]);

        (new AlertDetector)->run();

        $alert = Alert::where('src_ip', '203.0.113.40')->sole();
        $this->assertSame(1, $alert->details['cross_site']);
        $this->assertSame([], $this->lines());

        // The same address then attacks directly: that does ban.
        $this->hits('203.0.113.40', 1, 'sqli', '5 seconds');
        (new AlertDetector)->run();

        $this->assertCount(1, $this->lines());
        $this->assertStringContainsString('bawls ban 203.0.113.40 ', $this->lines()[0]);
    }

    public function test_an_ipv6_attacker_is_banned_as_a_whole_block(): void
    {
        // One customer or server holds a whole /64 and can use a new address
        // for every request, so banning the one seen would achieve nothing.
        $this->hits('2001:db8:1:2:aaaa:bbbb:cccc:7', 1, 'sqli');

        (new AlertDetector)->run();

        $this->assertStringContainsString('bawls ban 2001:db8:1:2::/64 rule=web_exploit', $this->lines()[0]);
    }

    public function test_a_never_block_address_spares_its_whole_ipv6_block(): void
    {
        // Your own IPv6 address changes within your network's block.
        config(['bawls.ban.never_block' => '2001:db8:1:2::50']);
        $this->hits('2001:db8:1:2:aaaa::7', 1, 'sqli');
        $this->hits('2001:db8:1:3::7', 1, 'sqli');   // a neighbour's block: banned

        (new AlertDetector)->run();

        $this->assertCount(1, $this->lines());
        $this->assertStringContainsString('bawls ban 2001:db8:1:3::/64 ', $this->lines()[0]);
    }
}
