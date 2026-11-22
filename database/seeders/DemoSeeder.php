<?php

namespace Database\Seeders;

use App\Models\Alert;
use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Services\AlertDetector;
use Illuminate\Database\Seeder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * A fictional day of attacks, for screenshots and demos:
 *
 *   php artisan db:seed --class=DemoSeeder
 *
 * Every address comes from the IPv4 documentation ranges (RFC 5737) and every
 * network from the documentation AS numbers (RFC 5398), so nothing in it
 * points at a real host. It only runs on a database with no events, so it
 * can't mix into real data. Alerts come from the real detector, run as each
 * burst of activity ends.
 */
class DemoSeeder extends Seeder
{
    private const SERVER = '192.0.2.10';

    private const DECOY_PORT = 8088;

    /** @var array<int, array<string, mixed>> */
    private const ATTACKERS = [
        ['ip' => '203.0.113.14', 'cc' => 'NL', 'city' => 'Amsterdam', 'lat' => 52.37, 'lng' => 4.90, 'asn' => 64501, 'org' => 'Example Hosting B.V.', 'rdns' => 'vps-14.hosting.example', 'gn' => 'malicious', 'abuse' => 100, 'ports' => [22, 80, 443], 'play' => 'exploit'],
        ['ip' => '203.0.113.77', 'cc' => 'US', 'city' => 'Ashburn', 'lat' => 39.04, 'lng' => -77.49, 'asn' => 64496, 'org' => 'Example Cloud LLC', 'rdns' => 'scan-77.cloud.example', 'gn' => 'benign', 'abuse' => 12, 'ports' => [], 'play' => 'scan'],
        ['ip' => '198.51.100.23', 'cc' => 'CN', 'city' => 'Shanghai', 'lat' => 31.23, 'lng' => 121.47, 'asn' => 64503, 'org' => 'Example Telecom', 'rdns' => null, 'gn' => 'malicious', 'abuse' => 96, 'ports' => [22], 'play' => 'ssh'],
        ['ip' => '198.51.100.140', 'cc' => 'RU', 'city' => 'Moscow', 'lat' => 55.75, 'lng' => 37.62, 'asn' => 64505, 'org' => 'Example Networks LLC', 'rdns' => null, 'gn' => 'malicious', 'abuse' => 88, 'ports' => [80], 'play' => 'wordpress'],
        ['ip' => '192.0.2.61', 'cc' => 'DE', 'city' => 'Frankfurt', 'lat' => 50.11, 'lng' => 8.68, 'asn' => 64507, 'org' => 'Beispiel Rechenzentrum GmbH', 'rdns' => 'static-61.rz.example', 'gn' => 'unknown', 'abuse' => 41, 'ports' => [22, 8080], 'play' => 'secrets'],
        ['ip' => '192.0.2.200', 'cc' => 'BR', 'city' => 'São Paulo', 'lat' => -23.55, 'lng' => -46.63, 'asn' => 64509, 'org' => 'Exemplo Telecom', 'rdns' => null, 'gn' => 'malicious', 'abuse' => 73, 'ports' => [], 'play' => 'sqli'],
        ['ip' => '203.0.113.190', 'cc' => 'VN', 'city' => 'Hanoi', 'lat' => 21.03, 'lng' => 105.85, 'asn' => 64510, 'org' => 'Example Mobile', 'rdns' => null, 'gn' => 'unknown', 'abuse' => 54, 'ports' => [], 'play' => 'traversal'],
        ['ip' => '198.51.100.7', 'cc' => 'SG', 'city' => 'Singapore', 'lat' => 1.35, 'lng' => 103.82, 'asn' => 64498, 'org' => 'Example Compute Pte', 'rdns' => 'exit-7.relay.example', 'gn' => 'malicious', 'abuse' => 100, 'ports' => [9001], 'tor' => true, 'play' => 'portscan'],
        ['ip' => '203.0.113.52', 'cc' => 'IN', 'city' => 'Mumbai', 'lat' => 19.08, 'lng' => 72.88, 'asn' => 64511, 'org' => 'Example Broadband', 'rdns' => null, 'gn' => 'unknown', 'abuse' => 37, 'ports' => [], 'play' => 'wordpress'],
        ['ip' => '198.51.100.88', 'cc' => 'KR', 'city' => 'Seoul', 'lat' => 37.57, 'lng' => 126.98, 'asn' => 64504, 'org' => 'Example Cable', 'rdns' => null, 'gn' => 'malicious', 'abuse' => 92, 'ports' => [23], 'play' => 'telnet'],
        ['ip' => '192.0.2.150', 'cc' => 'US', 'city' => 'Dallas', 'lat' => 32.78, 'lng' => -96.80, 'asn' => 64497, 'org' => 'Example Datacenter Inc.', 'rdns' => 'srv-150.dc.example', 'gn' => 'unknown', 'abuse' => 22, 'ports' => [3306], 'play' => 'phpmyadmin'],
        ['ip' => '203.0.113.9', 'cc' => 'GB', 'city' => 'London', 'lat' => 51.51, 'lng' => -0.13, 'asn' => 64502, 'org' => 'Example Colo Ltd', 'rdns' => null, 'gn' => 'malicious', 'abuse' => 81, 'ports' => [443], 'play' => 'exploit'],
        ['ip' => '192.0.2.33', 'cc' => 'FR', 'city' => 'Paris', 'lat' => 48.86, 'lng' => 2.35, 'asn' => 64508, 'org' => 'Exemple SAS', 'rdns' => null, 'gn' => null, 'abuse' => 0, 'ports' => [], 'play' => 'visitor'],
        ['ip' => '198.51.100.201', 'cc' => 'ZA', 'city' => 'Johannesburg', 'lat' => -26.20, 'lng' => 28.05, 'asn' => 64506, 'org' => 'Example Fibre', 'rdns' => null, 'gn' => 'unknown', 'abuse' => 15, 'ports' => [], 'play' => 'secrets'],
        ['ip' => '203.0.113.231', 'cc' => 'AU', 'city' => 'Sydney', 'lat' => -33.87, 'lng' => 151.21, 'asn' => 64499, 'org' => 'Example Internet Pty', 'rdns' => null, 'gn' => 'benign', 'abuse' => 0, 'ports' => [], 'play' => 'visitor'],
    ];

    /** @var array<int, string> */
    private const LATE = ['198.51.100.201', '203.0.113.52', '192.0.2.200'];

    private const SCAN_PATHS = [
        '/wp-admin/', '/xmlrpc.php', '/.env', '/.git/config', '/admin/', '/phpmyadmin/', '/pma/',
        '/server-status', '/actuator/health', '/boaform/admin/formLogin', '/cgi-bin/luci', '/HNAP1/',
        '/owa/', '/config.json', '/backup.zip', '/db.sql', '/solr/admin/info/system', '/.DS_Store',
        '/manager/html', '/remote/login', '/geoserver/web/', '/.vscode/sftp.json',
    ];

    private const USERNAMES = ['admin', 'administrator', 'root', 'wpadmin', 'test', 'user', 'editor', 'demo'];

    private const PASSWORDS = ['123456', 'admin', 'admin123', 'password', 'password1', 'qwerty', '12345678', '[masked:14 chars]', '[masked:11 chars]', '[masked:9 chars]'];

    private Sensor $decoy;

    private Sensor $ufw;

    /** @var array<int, string> */
    private array $noiseIps = [];

    public function run(): void
    {
        if (Event::query()->exists()) {
            $this->command?->warn('DemoSeeder only runs on a database with no events; nothing was added.');

            return;
        }

        // Fictional data must never reach the firewall or a webhook.
        config(['bawls.ban.enabled' => false, 'bawls.alert.webhook' => null]);
        mt_srand(2026);

        $end = now();
        $start = $end->copy()->subHours(23)->startOfHour();

        DB::transaction(function () use ($start, $end): void {
            $this->decoy = Sensor::factory()->create(['name' => 'web1-decoy', 'host' => 'web1', 'kind' => 'honeypot', 'last_seen_at' => $end]);
            $this->ufw = Sensor::factory()->create(['name' => 'web1-ufw', 'host' => 'web1', 'kind' => 'ufw', 'last_seen_at' => $end]);
            $this->noiseIps = $this->noiseAddresses();

            $this->intel();

            // Attackers play in time order; the detector runs as each burst ends,
            // so its windows see what it would have seen live.
            $bursts = [];
            foreach (self::ATTACKERS as $i => $attacker) {
                $at = $start->copy()->addMinutes(40 + intdiv($i * (23 * 60 - 80), count(self::ATTACKERS)) + mt_rand(0, 25));
                // A few land in the last quarter hour, so the live feed opens on them.
                $late = array_search($attacker['ip'], self::LATE, true);
                if ($late !== false) {
                    $at = $end->copy()->subMinutes(14 - 5 * $late);
                }
                $bursts[] = [$at, $attacker];
            }
            usort($bursts, fn (array $a, array $b): int => $a[0] <=> $b[0]);

            foreach ($bursts as [$at, $attacker]) {
                $last = $this->play($attacker, $at);
                Carbon::setTestNow($last);
                app(AlertDetector::class)->run();
            }
            Carbon::setTestNow();

            $this->firewallNoise($start, $end);
            $this->noiseIntel();

            // Ingest counts what each sensor delivered.
            foreach ([$this->decoy, $this->ufw] as $sensor) {
                $sensor->forceFill(['events_received' => $sensor->events()->count()])->save();
            }
        });

        // A worked inbox: some alerts already looked at.
        Alert::query()->where('rule', 'web_scan')->update(['status' => 'acked']);

        $this->command?->info(sprintf('Demo data: %d events, %d alerts.', Event::count(), Alert::count()));
    }

    /**
     * @param  array<string, mixed>  $a
     */
    private function play(array $a, Carbon $at): Carbon
    {
        $t = $at->copy();
        $step = fn (int $min, int $max): Carbon => $t->addSeconds(mt_rand($min, $max))->copy();

        switch ($a['play']) {
            case 'exploit':
                $this->web($a['ip'], $step(1, 4), 'GET', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '', 'cve_probe', 'eval-stdin.txt', 200, 'python-requests/2.32.3');
                $this->web($a['ip'], $step(2, 6), 'GET', '/index.php', 's=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id', 'rce', 'index.html', 200, 'python-requests/2.32.3');
                $this->web($a['ip'], $step(2, 6), 'POST', '/cgi-bin/.%2e/.%2e/.%2e/bin/sh', '', 'rce', '404.html', 404, 'python-requests/2.32.3', ['body' => 'echo;id']);
                $this->web($a['ip'], $step(1, 3), 'GET', '/.env', '', 'dirbust', 'dotenv.txt', 200, 'python-requests/2.32.3');
                break;

            case 'scan':
                foreach (self::SCAN_PATHS as $path) {
                    $this->web($a['ip'], $step(0, 2), 'GET', $path, '', $path === '/.env' ? 'dirbust' : 'scanner_ua', '404.html', 404, 'Mozilla/5.0 zgrab/0.x');
                }
                break;

            case 'wordpress':
                $this->web($a['ip'], $step(1, 5), 'GET', '/wp-login.php', '', 'benign', 'wp-login.html', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0');
                foreach (range(1, mt_rand(9, 16)) as $n) {
                    $this->web($a['ip'], $step(3, 20), 'POST', '/wp-login.php', '', 'login', 'wp-login.html', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0', [
                        'form' => ['log' => self::USERNAMES[mt_rand(0, 3)], 'pwd' => self::PASSWORDS[mt_rand(0, count(self::PASSWORDS) - 1)], 'wp-submit' => 'Log In'],
                    ]);
                }
                $this->web($a['ip'], $step(2, 9), 'POST', '/xmlrpc.php', '', 'login', 'xmlrpc.txt', 200, 'Mozilla/5.0 (compatible; WP-Scan)');
                break;

            case 'phpmyadmin':
                foreach (range(1, 7) as $n) {
                    $this->web($a['ip'], $step(4, 15), 'POST', '/phpmyadmin/index.php', '', 'login', 'phpmyadmin.html', 200, 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36', [
                        'form' => ['pma_username' => ['root', 'admin', 'pma'][mt_rand(0, 2)], 'pma_password' => self::PASSWORDS[mt_rand(0, count(self::PASSWORDS) - 1)]],
                    ]);
                }
                break;

            case 'secrets':
                foreach (['/.env', '/.git/config', '/.aws/credentials', '/config.json', '/wp-config.php.bak', '/.vscode/sftp.json', '/id_rsa'] as $path) {
                    $this->web($a['ip'], $step(1, 4), 'GET', $path, '', 'dirbust', 'dotenv.txt', 200, 'curl/8.5.0');
                }
                break;

            case 'sqli':
                foreach (["id=1' OR '1'='1", 'id=1 UNION SELECT NULL,version()--', "user=admin'--", 'q=1;WAITFOR DELAY \'0:0:5\'--'] as $query) {
                    $this->web($a['ip'], $step(2, 8), 'GET', '/products', $query, 'sqli', 'products.html', 200, 'sqlmap/1.8.4#stable (https://sqlmap.org)');
                }
                break;

            case 'traversal':
                $this->web($a['ip'], $step(1, 4), 'GET', '/static/../../../../etc/passwd', '', 'traversal', '404.html', 404, 'Go-http-client/1.1');
                $this->web($a['ip'], $step(1, 4), 'GET', '/download', 'file=....//....//etc/shadow', 'traversal', '404.html', 404, 'Go-http-client/1.1');
                $this->web($a['ip'], $step(3, 9), 'POST', '/pma/index.php', '', 'login', 'phpmyadmin.html', 200, 'Go-http-client/1.1', ['form' => ['pma_username' => 'root', 'pma_password' => '']]);
                break;

            case 'ssh':
                foreach (range(1, 24) as $n) {
                    $this->firewall($a['ip'], $step(1, 8), 22);
                }
                break;

            case 'telnet':
                foreach (range(1, 14) as $n) {
                    $this->firewall($a['ip'], $step(2, 10), 23);
                }
                break;

            case 'portscan':
                foreach ([21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017] as $port) {
                    $this->firewall($a['ip'], $step(0, 3), $port);
                }
                break;

            case 'visitor':
                foreach (['/', '/products', '/about', '/pricing'] as $path) {
                    $this->web($a['ip'], $step(8, 40), 'GET', $path, '', 'benign', (ltrim($path, '/') ?: 'index').'.html', 200, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15');
                }
                break;
        }

        return $t;
    }

    /**
     * @param  array<string, mixed>  $extra
     */
    private function web(string $ip, Carbon $at, string $method, string $path, string $query, string $signature, string $decoy, int $status, string $agent, array $extra = []): void
    {
        $form = $extra['form'] ?? [];
        $raw = [
            'method' => $method,
            'path' => $path,
            'query' => $query,
            'http_version' => 'HTTP/1.1',
            'host' => self::SERVER,
            'user_agent' => $agent,
            'accept' => '*/*',
            'accept_language' => str_contains($agent, 'Firefox') || str_contains($agent, 'Safari') ? 'en-US,en;q=0.9' : '',
            'headers' => ['Host' => self::SERVER, 'User-Agent' => $agent, 'Accept' => '*/*'],
            'header_order' => ['Host', 'User-Agent', 'Accept'],
            'form' => $form,
            'body_excerpt' => $extra['body'] ?? '',
            'signature' => $signature,
            'decoy' => $decoy,
            'status' => $status,
        ];
        if ($method === 'POST' && $signature === 'login') {
            $raw['login_attempt'] = true;
        }

        $this->event($this->decoy, $ip, $at, 'honeypot_http', self::DECOY_PORT, 'probed', $raw);
    }

    private function firewall(string $ip, Carbon $at, int $port): void
    {
        $this->event($this->ufw, $ip, $at, 'ufw_block', $port, 'blocked', null);
    }

    /**
     * @param  array<string, mixed>|null  $raw
     */
    private function event(Sensor $sensor, string $ip, Carbon $at, string $source, int $port, string $action, ?array $raw): void
    {
        Event::create([
            'occurred_at' => $at,
            'sensor_id' => $sensor->id,
            'host' => 'web1',
            'source' => $source,
            'direction' => 'in',
            'proto' => $source === 'ufw_block' && $port === 53 ? 'udp' : 'tcp',
            'src_ip' => $ip,
            'src_port' => mt_rand(1024, 65535),
            'dst_ip' => self::SERVER,
            'dst_port' => $port,
            'iface' => $source === 'ufw_block' ? 'eth0' : null,
            'action' => $action,
            'raw' => $raw,
        ]);
    }

    /** The background hum of the internet: blocked probes all day, busier at night. */
    private function firewallNoise(Carbon $start, Carbon $end): void
    {
        $ports = [22, 22, 22, 23, 80, 443, 445, 3389, 3389, 5900, 8080, 8443, 6379, 25, 53, 1433];
        for ($hour = $start->copy(); $hour < $end; $hour->addHour()) {
            $busy = in_array($hour->hour, [1, 2, 3, 4, 13, 14], true) ? 2 : 1;
            foreach (range(1, mt_rand(18, 34) * $busy) as $n) {
                $at = $hour->copy()->addSeconds(mt_rand(0, 3599));
                if ($at > $end) {
                    continue;
                }
                $this->firewall($this->noiseIps[mt_rand(0, count($this->noiseIps) - 1)], $at, $ports[mt_rand(0, count($ports) - 1)]);
            }
        }
    }

    /** Firewall-blocked addresses get enriched too: somewhere ordinary, mostly unremarkable. */
    private function noiseIntel(): void
    {
        $places = [
            ['US', 'Chicago', 41.88, -87.63], ['US', 'Los Angeles', 34.05, -118.24], ['CN', 'Beijing', 39.90, 116.40],
            ['RU', 'Saint Petersburg', 59.93, 30.36], ['IN', 'Bengaluru', 12.97, 77.59], ['BR', 'Rio de Janeiro', -22.91, -43.17],
            ['DE', 'Berlin', 52.52, 13.40], ['NL', 'Rotterdam', 51.92, 4.48], ['VN', 'Ho Chi Minh City', 10.82, 106.63],
            ['ID', 'Jakarta', -6.21, 106.85], ['TR', 'Istanbul', 41.01, 28.98], ['KR', 'Busan', 35.18, 129.08],
            ['GB', 'Manchester', 53.48, -2.24], ['FR', 'Marseille', 43.30, 5.37], ['UA', 'Kyiv', 50.45, 30.52],
            ['MX', 'Mexico City', 19.43, -99.13], ['JP', 'Tokyo', 35.68, 139.69], ['IR', 'Tehran', 35.69, 51.39],
        ];
        $classes = ['unknown', 'unknown', 'unknown', 'malicious', 'benign'];
        foreach ($this->noiseIps as $i => $ip) {
            [$cc, $city, $lat, $lng] = $places[$i % count($places)];
            $asn = 64496 + mt_rand(0, 15);
            IpIntel::create([
                'ip' => $ip,
                'is_private' => false,
                'country' => $cc,
                'city' => $city,
                'latitude' => round($lat + mt_rand(-40, 40) / 100, 2),
                'longitude' => round($lng + mt_rand(-40, 40) / 100, 2),
                'asn' => $asn,
                'as_org' => "Example Net AS{$asn}",
                'abuse_score' => mt_rand(0, 60),
                'abuse_reports' => mt_rand(0, 40),
                'greynoise_class' => $classes[mt_rand(0, count($classes) - 1)],
                'open_ports' => [],
                'tor_exit' => false,
                'checked_at' => now(),
            ]);
        }
    }

    /** @return array<int, string> */
    private function noiseAddresses(): array
    {
        $ips = [];
        foreach (['192.0.2', '198.51.100', '203.0.113'] as $net) {
            foreach (range(1, 14) as $n) {
                $ips[] = $net.'.'.mt_rand(100, 254);
            }
        }

        return array_values(array_diff(array_unique($ips), array_column(self::ATTACKERS, 'ip'), [self::SERVER]));
    }

    /** What enrichment would have found. Visitors who only browsed are never looked up. */
    private function intel(): void
    {
        foreach (self::ATTACKERS as $a) {
            if ($a['play'] === 'visitor') {
                continue;
            }
            IpIntel::create([
                'ip' => $a['ip'],
                'is_private' => false,
                'country' => $a['cc'],
                'city' => $a['city'],
                'latitude' => $a['lat'],
                'longitude' => $a['lng'],
                'asn' => $a['asn'],
                'as_org' => $a['org'],
                'rdns' => $a['rdns'],
                'abuse_score' => $a['abuse'],
                'abuse_reports' => intdiv($a['abuse'] * 7, 3),
                'greynoise_class' => $a['gn'],
                'open_ports' => $a['ports'],
                'tor_exit' => $a['tor'] ?? false,
                'abuse_contact' => 'abuse@'.strtolower(preg_replace('/[^A-Za-z]+/', '', explode(' ', $a['org'])[0])).'.example',
                'checked_at' => now(),
            ]);
        }
    }
}
