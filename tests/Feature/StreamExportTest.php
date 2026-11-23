<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use App\Models\User;
use App\Services\Settings;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** The stream's Export: everything its display filter matches, as CSV or JSON. */
class StreamExportTest extends TestCase
{
    use RefreshDatabase;

    private Sensor $sensor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->actingAs(User::factory()->create());
        $this->sensor = Sensor::factory()->create(['name' => 'web1-decoy']);
    }

    /**
     * @param  array<string, mixed>  $raw
     */
    private function request(string $ip, string $path, string $signature, int $minutesAgo, array $raw = []): Event
    {
        return Event::factory()->create([
            'sensor_id' => $this->sensor->id, 'source' => 'honeypot_http', 'action' => 'probed',
            'src_ip' => $ip, 'src_port' => 40000, 'dst_ip' => '192.0.2.10', 'dst_port' => 8088,
            'occurred_at' => now()->subMinutes($minutesAgo),
            'raw' => ['method' => 'GET', 'path' => $path, 'query' => '', 'signature' => $signature, 'status' => 404, ...$raw],
        ]);
    }

    /**
     * @return list<list<string>>
     */
    private function csv(string $query): array
    {
        $body = $this->get("/stream/export?{$query}")->assertOk()->streamedContent();

        return array_map(fn (string $line): array => str_getcsv($line, escape: ''), array_filter(explode("\n", $body)));
    }

    public function test_csv_has_the_streams_columns_for_every_match_not_just_the_rows_on_screen(): void
    {
        app(Settings::class)->update(['timezone' => 'America/New_York']);
        $old = $this->request('203.0.113.7', '/.env', 'dirbust', 30);
        $new = $this->request('203.0.113.7', '/.git/config', 'dirbust', 5);
        Event::factory()->count(250)->create(['src_ip' => '198.51.100.20', 'occurred_at' => now()->subHour()]);

        $rows = $this->csv('format=csv&f='.urlencode('src == 203.0.113.7'));
        $this->assertSame(['No.', 'Time (America/New_York)', 'Source', 'Destination', 'Protocol', 'Info'], $rows[0]);
        $this->assertSame([(string) $new->id, (string) $old->id], array_column(array_slice($rows, 1), 0), 'newest first, like the stream');
        $this->assertSame([
            (string) $new->id,
            $new->occurred_at->setTimezone('America/New_York')->format('Y-m-d H:i:s'),
            '203.0.113.7:40000', '192.0.2.10:8088', 'HTTP', 'GET /.git/config · dirbust → 404',
        ], $rows[1]);

        // No filter: all 252, though the stream shows 200 at a time.
        $this->assertCount(253, $this->csv('format=csv'));
    }

    public function test_json_carries_each_whole_event(): void
    {
        $event = $this->request('203.0.113.7', '/wp-login.php', 'login', 5, ['method' => 'POST', 'form' => ['log' => 'admin'], 'login_attempt' => true]);

        $response = $this->get('/stream/export?format=json&f='.urlencode('sig == login'))->assertOk();
        $this->assertStringContainsString('application/json', $response->headers->get('Content-Type'));
        $this->assertStringContainsString('attachment; filename=bawls-events-', $response->headers->get('Content-Disposition'));

        $events = json_decode($response->streamedContent(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertCount(1, $events);
        $this->assertSame($event->id, $events[0]['id']);
        $this->assertSame('web1-decoy', $events[0]['sensor']);
        $this->assertSame('login', $events[0]['kind']);
        $this->assertSame(['log' => 'admin'], $events[0]['raw']['form']);
        $this->assertSame('POST /wp-login.php · login → 404', $events[0]['info']);
    }

    public function test_an_empty_match_is_still_a_valid_file(): void
    {
        $this->assertSame([], json_decode($this->get('/stream/export?format=json&f='.urlencode('port == 1'))->streamedContent(), true));
        $this->assertCount(1, $this->csv('format=csv&f='.urlencode('port == 1')));
    }

    public function test_attacker_text_that_a_spreadsheet_would_run_opens_as_plain_text(): void
    {
        $this->request('203.0.113.7', '/x', 'benign', 5, ['method' => '=HYPERLINK("http://example.com")']);

        $rows = $this->csv('format=csv');
        $this->assertStringStartsWith("'=HYPERLINK", $rows[1][5]);
    }

    public function test_a_broken_filter_is_refused(): void
    {
        $this->get('/stream/export?format=csv&f='.urlencode('src ==='))->assertStatus(422);
    }

    public function test_signed_out_visitors_get_a_404(): void
    {
        auth()->logout();

        $this->get('/stream/export?format=csv')->assertNotFound();
    }
}
