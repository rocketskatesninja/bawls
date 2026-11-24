<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use App\Services\ProbeCatalog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use ReflectionClassConstant;
use Tests\TestCase;

/** The digest's definitions: what a probe is after, in plain English. */
class ProbeCatalogTest extends TestCase
{
    use RefreshDatabase;

    /** Real rows from a week of a live decoy's digest, and what they are. */
    public function test_probes_from_a_real_digest_get_the_right_definition(): void
    {
        $catalog = new ProbeCatalog;
        $cases = [
            ['GET', '/id_rsa', null, 'SSH keys'],
            ['GET', '/v2/_catalog', null, 'Docker registry'],
            ['GET', '/telescope/requests', null, 'Laravel Telescope'],
            ['GET', '/owa/', null, 'Microsoft Exchange'],
            ['GET', '/manager/html', null, 'Tomcat Manager'],
            ['GET', '/console/', null, 'Admin console (WebLogic)'],
            ['GET', '/api/swagger.json', null, 'API documentation'],
            ['GET', '/', 'author=1&feed=rss2', 'WordPress author lookup'],
            ['POST', '/', 'rest_route=/batch/v1', 'WordPress REST API'],
            ['POST', '/graphql', null, 'GraphQL'],
            ['GET', '/lander', null, 'Ad / phishing lander'],
            ['GET', '/.claude/settings.local.json', null, 'AI coding-agent config'],
            ['GET', '/.cursor/mcp.json', null, 'AI coding-agent config'],
            ['GET', '/wp-config.php', null, 'WordPress config'],
            ['GET', '/.netrc', null, 'Saved logins (.netrc)'],
            ['GET', '/storage/logs/laravel.log', null, 'Log file'],
            ['GET', '/api/v1/version', null, 'Version / status check'],
            ['GET', '/env.prod.js', null, 'Front-end config'],
            ['GET', '/web/debug/default/view', 'panel=config', 'Yii debug panel'],
            ['GET', '/sitemap_index.xml', null, 'Sitemap'],
            ['GET', '/whm', null, 'cPanel / WHM'],
            ['GET', '/env', null, 'Environment dump'],
            ['GET', '/login.html', null, 'Login or admin page'],
            ['GET', '/', 'url=.env', 'Environment file (.env)'],
            ['GET', '/index.php', 's=/Index/\\think\\app/invokefunction', 'ThinkPHP'],
            ['PROPFIND', '/', null, 'WebDAV'],
            ['CONNECT', 'example.com:443', null, 'Open proxy test'],
        ];
        foreach ($cases as [$method, $path, $query, $title]) {
            $explained = $catalog->explain($method, $path, $query);
            $this->assertSame($title, $explained['title'], "{$method} {$path}?{$query}");
            $this->assertTrue($explained['known']);
        }

        $plugin = $catalog->explain('GET', '/wp-content/plugins/revslider/readme.txt');
        $this->assertSame('WordPress plugin', $plugin['title']);
        $this->assertStringContainsString('"revslider"', $plugin['text']);
    }

    public function test_anything_unknown_gets_a_best_guess_marked_as_one(): void
    {
        $catalog = new ProbeCatalog;
        $cases = [
            ['POST', '/zzq-unknown', null, 'Blind exploit attempt'],
            ['GET', '/.zzq-hidden', null, 'Hidden file'],
            ['GET', '/zzq-tool.php', null, 'Script check'],
            ['GET', '/zzq-export.json', null, 'File hunting'],
            ['GET', '/api/zzq/items', null, 'API discovery'],
            ['GET', '/zzq', 'a=1', 'Parameter probe'],
            ['GET', '/zzq-unknown', null, 'Wordlist scan'],
        ];
        foreach ($cases as [$method, $path, $query, $title]) {
            $explained = $catalog->explain($method, $path, $query);
            $this->assertSame($title, $explained['title'], "{$method} {$path}");
            $this->assertFalse($explained['known']);
        }
    }

    public function test_every_pattern_compiles_and_every_text_reads_cleanly(): void
    {
        foreach ((new ReflectionClassConstant(ProbeCatalog::class, 'FAMILIES'))->getValue() as [$pattern, $title, $text]) {
            $this->assertNotFalse(@preg_match($pattern, ''), "bad pattern for {$title}");
            $this->assertStringNotContainsString('%', str_replace('%s', '', $text), "stray % in {$title}");
        }
    }

    public function test_each_digest_row_carries_its_definition(): void
    {
        $sensor = Sensor::factory()->create();
        Event::factory()->create([
            'sensor_id' => $sensor->id, 'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => '203.0.113.5',
            'occurred_at' => now()->subHour(),
            'raw' => ['method' => 'GET', 'path' => '/v2/_catalog', 'query' => '', 'signature' => 'scanner_ua', 'status' => 404],
        ]);

        $rows = $this->signIn()->get('/')->viewData('page')['props']['unrecognised']['rows'];

        $this->assertSame('Docker registry', $rows[0]['explain']['title']);
        $this->assertTrue($rows[0]['explain']['known']);
    }
}
