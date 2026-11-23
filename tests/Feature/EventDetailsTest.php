<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\IpIntel;
use App\Models\Sensor;
use App\Models\User;
use App\Services\DisplayFilter;
use App\Services\Settings;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class EventDetailsTest extends TestCase
{
    use RefreshDatabase;

    private function decoyEvent(array $raw = []): Event
    {
        return Event::factory()->create([
            'sensor_id' => (Sensor::firstWhere('name', 'web1-decoy') ?? Sensor::factory()->create(['name' => 'web1-decoy']))->id,
            'source' => 'honeypot_http', 'action' => 'probed', 'proto' => 'tcp',
            'src_ip' => '203.0.113.9', 'src_port' => 40000, 'dst_ip' => '192.0.2.20', 'dst_port' => 80, 'iface' => null,
            'raw' => [
                'method' => 'POST', 'path' => '/wp-login.php', 'query' => 'redirect_to=/wp-admin',
                'host' => 'bawls.example', 'user_agent' => 'Mozilla/5.0 "quoted"',
                'headers' => ['Host' => 'bawls.example', 'User-Agent' => 'Mozilla/5.0 "quoted"', 'Accept' => '*/*'],
                'header_order' => ['User-Agent', 'Host', 'Accept'],
                'form' => ['log' => 'admin', 'pwd' => '[masked:9 chars]'],
                'signature' => 'login', 'login_attempt' => true, 'status' => 200,
                ...$raw,
            ],
        ]);
    }

    /** @return array<string, array{value: string, filter: string|null}> fields by "Section › Label" */
    private function fields(Event $event): array
    {
        $fields = [];
        foreach ($this->actingAs(User::factory()->create())->getJson("/events/{$event->id}")->assertOk()->json('sections') as $section) {
            foreach ($section['fields'] as $field) {
                $fields["{$section['title']} › {$field['label']}"] = ['value' => $field['value'], 'filter' => $field['filter']];
            }
        }

        return $fields;
    }

    public function test_a_decoy_event_comes_apart_like_a_packet_with_a_filter_for_each_field(): void
    {
        $event = $this->decoyEvent();
        IpIntel::create(['ip' => '203.0.113.9', 'country' => 'NL', 'asn' => 64500, 'as_org' => 'Example Hosting', 'checked_at' => now()]);

        $fields = $this->fields($event);

        $this->assertSame(['value' => (string) $event->id, 'filter' => "no == {$event->id}"], $fields['Frame › No.']);
        $this->assertSame('web1-decoy', $fields['Frame › Sensor']['value']);
        $this->assertSame('src == 203.0.113.9', $fields['Network › Source']['filter']);
        $this->assertSame('dst.port == 80', $fields['Network › Destination port']['filter']);
        $this->assertSame('path == /wp-login.php', $fields['HTTP › Path']['filter']);
        $this->assertSame('ua == "Mozilla/5.0 \\"quoted\\""', $fields['HTTP › User agent']['filter']);
        $this->assertSame(['value' => 'yes', 'filter' => 'login'], $fields['Detection › Login attempt']);
        $this->assertSame('sig == login', $fields['Detection › Signature']['filter']);
        $this->assertSame('country == NL', $fields['Source › Country']['filter']);
        $this->assertSame(['value' => 'no', 'filter' => '!banned'], $fields['Source › Banned now']);
        $this->assertSame('[masked:9 chars]', $fields['Form › pwd']['value']);
        $this->assertArrayNotHasKey('Network › Interface', $fields, 'empty fields are left out');

        // Every filter the pane offers must parse.
        foreach (array_filter(array_column($fields, 'filter')) as $filter) {
            $this->assertInstanceOf(DisplayFilter::class, DisplayFilter::parse($filter), $filter);
        }
    }

    public function test_the_time_is_in_the_display_zone_with_utc_beside_it_when_they_differ(): void
    {
        $event = $this->decoyEvent();
        $event->update(['occurred_at' => '2026-11-20 14:00:05']);

        $this->assertSame('2026-11-20 14:00:05', $this->fields($event)['Frame › Time · UTC']['value']);
        $this->assertCount(1, preg_grep('/^Frame › Time/', array_keys($this->fields($event))), 'UTC is shown once');

        app(Settings::class)->update(['timezone' => 'America/New_York']);
        app()->forgetScopedInstances();
        $fields = $this->fields($event);

        $this->assertSame('2026-11-20 09:00:05', $fields['Frame › Time · EST']['value']);
        $this->assertSame('2026-11-20 14:00:05', $fields['Frame › Time · UTC']['value']);
    }

    public function test_headers_keep_the_order_the_client_sent_them_in(): void
    {
        $response = $this->actingAs(User::factory()->create())->getJson("/events/{$this->decoyEvent()->id}");

        $headers = collect($response->json('sections'))->firstWhere('title', 'Headers, in the order sent');
        $this->assertSame(['User-Agent', 'Host', 'Accept'], array_column($headers['fields'], 'label'));
    }

    public function test_the_raw_record_comes_along_for_the_raw_view(): void
    {
        $this->actingAs(User::factory()->create())->getJson("/events/{$this->decoyEvent()->id}")
            ->assertJsonPath('raw.form.log', 'admin')
            ->assertJsonPath('kind', 'login')
            ->assertJsonPath('dossier', '/ip/203.0.113.9');
    }

    public function test_a_firewall_event_has_no_http_sections(): void
    {
        $event = Event::factory()->create(['dst_port' => 22]);

        $titles = collect($this->actingAs(User::factory()->create())->getJson("/events/{$event->id}")->json('sections'))->pluck('title')->all();

        $this->assertSame(['Frame', 'Network', 'Source'], $titles);
    }

    public function test_signed_out_visitors_and_unknown_events_get_a_404(): void
    {
        $event = $this->decoyEvent();

        $this->get("/events/{$event->id}")->assertNotFound();
        $this->actingAs(User::factory()->create())->get('/events/999999')->assertNotFound();
    }

    public function test_stream_rows_carry_their_kind_and_a_one_line_summary(): void
    {
        $this->decoyEvent();
        $this->decoyEvent(['signature' => 'sqli', 'login_attempt' => false, 'method' => 'GET', 'path' => '/', 'query' => "id=1'", 'status' => 404]);
        $this->decoyEvent(['signature' => null, 'login_attempt' => false, 'method' => 'GET', 'path' => '/about', 'query' => null]);
        Event::factory()->create(['proto' => 'udp', 'dst_port' => 3389, 'iface' => 'eth0']);

        $rows = collect($this->actingAs(User::factory()->create())->get('/')->viewData('page')['props']['stream']['rows'])
            ->map(fn (array $row): string => "{$row['kind']} | {$row['proto']} | {$row['info']}")
            ->sort()->values()->all();

        $this->assertSame([
            'exploit | HTTP | GET /?id=1\' · sqli → 404',
            'firewall | UDP | port 3389 blocked · eth0',
            'login | HTTP | POST /wp-login.php?redirect_to=/wp-admin · login → 200',
            'page | HTTP | GET /about → 200',
        ], $rows);
    }
}
