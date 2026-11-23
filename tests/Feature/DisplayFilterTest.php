<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Services\DisplayFilter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class DisplayFilterTest extends TestCase
{
    use RefreshDatabase;

    /** @var array<string, int> label => event id */
    private array $events = [];

    protected function setUp(): void
    {
        parent::setUp();
        $sensor = Sensor::factory()->create();
        $ufw = fn (string $src, int $srcPort, int $dstPort, string $proto, string $at): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'source' => 'ufw_block', 'proto' => $proto, 'action' => 'blocked',
            'src_ip' => $src, 'src_port' => $srcPort, 'dst_ip' => '192.0.2.10', 'dst_port' => $dstPort,
            'occurred_at' => Carbon::parse($at, 'UTC'),
        ]);
        $http = fn (string $src, int $dstPort, array $raw, string $at): Event => Event::factory()->create([
            'sensor_id' => $sensor->id, 'source' => 'honeypot_http', 'proto' => 'tcp', 'action' => 'probed',
            'src_ip' => $src, 'src_port' => 40000, 'dst_ip' => '192.0.2.20', 'dst_port' => $dstPort,
            'iface' => null, 'raw' => $raw, 'occurred_at' => Carbon::parse($at, 'UTC'),
        ]);

        $this->events = [
            'ssh' => $ufw('203.0.113.9', 51234, 22, 'tcp', '2026-11-20 13:59:59')->id,
            'rdp' => $ufw('198.51.100.4', 6021, 3389, 'udp', '2026-11-20 14:10:00')->id,
            'login' => $http('203.0.113.9', 80, [
                'method' => 'POST', 'path' => '/wp-login.php', 'host' => 'bawls.example', 'user_agent' => 'Mozilla/5.0',
                'signature' => 'login', 'login_attempt' => true, 'status' => 200,
            ], '2026-11-20 14:20:00')->id,
            'sqli' => $http('192.0.2.77', 443, [
                'method' => 'GET', 'path' => '/', 'query' => "id=1' OR 1=1--", 'user_agent' => 'sqlmap/1.7',
                'signature' => 'sqli', 'status' => 404,
            ], '2026-11-20 14:59:59')->id,
            'home' => $http('203.0.113.50', 80, ['method' => 'GET', 'path' => '/', 'status' => 200], '2026-11-20 15:00:00')->id,
            'percent' => $http('203.0.113.51', 80, [
                'method' => 'GET', 'path' => '/100%_done', 'signature' => 'benign', 'status' => 200,
            ], '2026-11-20 15:30:00')->id,
        ];
        IpIntel::create(['ip' => '203.0.113.9', 'country' => 'NL', 'asn' => 64500, 'as_org' => 'Example Hosting', 'checked_at' => now()]);
        IpIntel::create(['ip' => '192.0.2.77', 'country' => 'CN', 'asn' => 64501, 'as_org' => 'Other Net', 'checked_at' => now()]);
    }

    /** @return list<string> the labels of the events a filter matches */
    private function matching(string $filter, string $timezone = 'UTC'): array
    {
        $ids = DisplayFilter::parse($filter)->apply(Event::query(), $timezone)->pluck('id')->all();
        $labels = array_keys(array_intersect($this->events, $ids));
        sort($labels);

        return $labels;
    }

    /** @return array<string, array{string, list<string>}> */
    public static function filters(): array
    {
        return [
            'source address' => ['src == 203.0.113.9', ['login', 'ssh']],
            'either address' => ['ip == 192.0.2.20', ['home', 'login', 'percent', 'sqli']],
            'a /24' => ['src == 203.0.113.0/24', ['home', 'login', 'percent', 'ssh']],
            'not a /24' => ['src != 203.0.113.0/24', ['rdp', 'sqli']],
            'port' => ['port == 22', ['ssh']],
            'port set' => ['dst.port in {22 3389}', ['rdp', 'ssh']],
            'port range' => ['dst.port >= 3389', ['rdp']],
            'protocol, any case' => ['proto == UDP', ['rdp']],
            'decoy events' => ['http', ['home', 'login', 'percent', 'sqli']],
            'firewall events' => ['ufw', ['rdp', 'ssh']],
            'login attempts' => ['login', ['login']],
            'signature' => ['sig == sqli', ['sqli']],
            'benign includes unlabelled' => ['sig == benign', ['home', 'percent']],
            'not benign, decoy only' => ['sig != benign', ['login', 'sqli']],
            'signature set' => ['sig in {sqli login}', ['login', 'sqli']],
            'contains, any case' => ['path contains "WP-"', ['login']],
            'contains takes % literally' => ['path contains "%"', ['percent']],
            'contains takes _ literally' => ['path contains "_"', ['percent']],
            '!= needs the field' => ['path != "/"', ['login', 'percent']],
            '!( == ) does not' => ['!(path == "/")', ['login', 'percent', 'rdp', 'ssh']],
            'query' => ['query contains "1=1"', ['sqli']],
            'user agent' => ['ua contains sqlmap', ['sqli']],
            'method' => ['method == post', ['login']],
            'status' => ['status == 404', ['sqli']],
            'host header' => ['http.host == bawls.example', ['login']],
            'country' => ['country == nl', ['login', 'ssh']],
            'country, known and different' => ['country != NL', ['sqli']],
            'asn' => ['asn == 64501', ['sqli']],
            'network name' => ['org contains "hosting"', ['login', 'ssh']],
            'an hour' => ['time >= "2026-11-20 14:00" && time < "2026-11-20 15:00"', ['login', 'rdp', 'sqli']],
            'a minute' => ['time == "2026-11-20 14:20"', ['login']],
            'a day' => ['time == 2026-11-20', ['home', 'login', 'percent', 'rdp', 'sqli', 'ssh']],
            '&& before ||' => ['ufw || http && sig == sqli', ['rdp', 'sqli', 'ssh']],
            'parentheses' => ['(ufw || http) && src == 203.0.113.9', ['login', 'ssh']],
            'word operators' => ['not ufw and src eq 203.0.113.9', ['login']],
            'wireshark names' => ['ip.src == 192.0.2.77 && http.request.uri == "/" && tcp.dstport eq 443', ['sqli']],
        ];
    }

    /** @param list<string> $expected */
    #[DataProvider('filters')]
    public function test_it_matches(string $filter, array $expected): void
    {
        $this->assertSame($expected, $this->matching($filter));
    }

    public function test_times_are_read_in_the_display_zone(): void
    {
        // 14:00-15:00 UTC is 09:00-10:00 in New York in November.
        $this->assertSame(['login', 'rdp', 'sqli'], $this->matching(
            'time >= "2026-11-20 09:00" && time < "2026-11-20 10:00"', 'America/New_York',
        ));
    }

    public function test_banned_reads_fail2bans_list(): void
    {
        $export = storage_path('framework/testing/banned.txt');
        @mkdir(dirname($export), 0777, true);
        file_put_contents($export, "# utc-offset +0000\n203.0.113.9 \t2026-11-20 14:00:00 + 604800 = 2026-11-27 14:00:00\n");
        config(['bawls.ban.export' => $export]);

        $this->assertSame(['login', 'ssh'], $this->matching('banned'));
        $this->assertSame(['home', 'percent', 'rdp', 'sqli'], $this->matching('!banned'));

        unlink($export);
        $this->assertSame([], $this->matching('banned'));
    }

    public function test_the_event_number(): void
    {
        $this->assertSame(['sqli'], $this->matching('no == '.$this->events['sqli']));
    }
}
