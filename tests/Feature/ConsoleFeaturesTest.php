<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\Event;
use App\Models\Sensor;
use App\Models\User;
use App\Services\Blocklist;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ConsoleFeaturesTest extends TestCase
{
    use RefreshDatabase;

    private function alert(string $ip, string $status = 'open'): Alert
    {
        return Alert::factory()->create(['src_ip' => $ip, 'status' => $status]);
    }

    public function test_alerts_can_be_acknowledged_and_resolved(): void
    {
        $alert = $this->alert('203.0.113.9');
        $user = User::factory()->create();

        $this->actingAs($user)->post("/alerts/{$alert->id}/ack")->assertRedirect();
        $this->assertSame('acked', $alert->fresh()->status);

        $this->actingAs($user)->post("/alerts/{$alert->id}/resolve");
        $this->assertSame('resolved', $alert->fresh()->status);
    }

    public function test_all_open_alerts_can_be_closed_at_once_up_to_the_newest_one_seen(): void
    {
        $first = $this->alert('203.0.113.9');
        $acked = $this->alert('203.0.113.10', 'acked');
        $second = $this->alert('203.0.113.11');
        $later = $this->alert('203.0.113.12');   // opened after the page was drawn
        $user = User::factory()->create();

        $this->post('/alerts/resolve', ['through' => $second->id])->assertNotFound();
        $this->actingAs($user)->post('/alerts/resolve')->assertSessionHasErrors('through');
        $this->assertSame('open', $first->fresh()->status);

        $this->actingAs($user)->post('/alerts/resolve', ['through' => $second->id])->assertRedirect();
        $this->assertSame(['resolved', 'acked', 'resolved', 'open'], [
            $first->fresh()->status, $acked->fresh()->status, $second->fresh()->status, $later->fresh()->status,
        ]);

        $this->actingAs($user)->post('/alerts/ack', ['through' => $later->id])->assertRedirect();
        $this->assertSame('acked', $later->fresh()->status);
        $this->assertSame('resolved', $first->fresh()->status);
    }

    public function test_alert_actions_require_auth(): void
    {
        $alert = $this->alert('203.0.113.9');
        $this->post("/alerts/{$alert->id}/ack")->assertNotFound();
        $this->assertSame('open', $alert->fresh()->status);
    }

    public function test_blocklist_lists_external_alerted_ips_only(): void
    {
        $this->alert('203.0.113.9');   // external → listed
        $this->alert('10.0.0.5');   // private → excluded

        $ips = Blocklist::ips();
        $this->assertTrue($ips->contains('203.0.113.9'));
        $this->assertFalse($ips->contains('10.0.0.5'));

        $this->signIn()->get('/blocklist.txt')
            ->assertOk()->assertSee('203.0.113.9')->assertDontSee('10.0.0.5');
    }

    public function test_credentials_page_lists_login_attempts(): void
    {
        $sensor = Sensor::factory()->create();
        Event::create([
            'occurred_at' => now(), 'sensor_id' => $sensor->id, 'host' => 'web1', 'source' => 'honeypot_http',
            'direction' => 'in', 'proto' => 'tcp', 'src_ip' => '203.0.113.9', 'dst_ip' => '10.0.0.80',
            'dst_port' => 8088, 'action' => 'probed',
            'raw' => ['path' => '/wp-login.php', 'signature' => 'login', 'form' => ['log' => 'admin', 'pwd' => 'password']],
        ]);

        $this->signIn()->get('/credentials')
            ->assertInertia(fn (Assert $p) => $p->component('Credentials', false)
                ->where('attempts.0.username', 'admin')
                ->where('attempts.0.password', 'password'));
    }

    public function test_credentials_lists_every_flagged_login_including_ones_carrying_an_attack(): void
    {
        $sensor = Sensor::factory()->create();
        $post = fn (string $ip, int $minutesAgo, array $raw) => Event::create([
            'occurred_at' => now()->subMinutes($minutesAgo), 'sensor_id' => $sensor->id, 'host' => 'web1',
            'source' => 'honeypot_http', 'direction' => 'in', 'proto' => 'tcp', 'src_ip' => $ip,
            'dst_ip' => '127.0.0.1', 'dst_port' => 8088, 'action' => 'probed', 'raw' => $raw + ['method' => 'POST'],
        ]);

        $post('203.0.113.21', 3, ['path' => '/phpmyadmin/index.php', 'signature' => 'login', 'login_attempt' => true,
            'form' => ['pma_username' => 'root', 'pma_password' => 'toor']]);
        $post('203.0.113.22', 2, ['path' => '/wp-login.php', 'signature' => 'sqli', 'login_attempt' => true,
            'form' => ['log' => "admin' or 1=1--", 'pwd' => '[masked:3 chars]']]);
        $post('203.0.113.23', 1, ['path' => '/contact', 'signature' => 'benign', 'form' => ['name' => 'Pat']]);

        $this->signIn()->get('/credentials')
            ->assertInertia(fn (Assert $p) => $p->component('Credentials', false)
                ->has('attempts', 2)                                      // the /contact post is not a login
                ->where('attempts.0.username', "admin' or 1=1--")
                ->where('attempts.0.attack', 'sqli')
                ->where('attempts.1.username', 'root')                   // phpMyAdmin field names
                ->where('attempts.1.password', 'toor')
                ->where('attempts.1.attack', null));
    }

    public function test_repeated_passwords_are_counted_masked_ones_by_their_fingerprint(): void
    {
        $sensor = Sensor::factory()->create();
        $login = fn (string $ip, string $password, string $field = 'pwd') => Event::create([
            'occurred_at' => now(), 'sensor_id' => $sensor->id, 'host' => 'web1', 'source' => 'honeypot_http',
            'direction' => 'in', 'proto' => 'tcp', 'src_ip' => $ip, 'dst_ip' => '10.0.0.80', 'dst_port' => 8088,
            'action' => 'probed', 'raw' => ['path' => '/wp-login.php', 'signature' => 'login', 'login_attempt' => true,
                'form' => ['log' => 'admin', $field => $password]],
        ]);
        $secret = '[masked:14 chars #a1b2c3d4e5f6]';
        $login('203.0.113.1', $secret);
        $login('203.0.113.2', $secret);
        $login('203.0.113.2', $secret, 'pma_password');   // phpMyAdmin's field counts too
        $login('203.0.113.3', '123456');
        $login('203.0.113.4', '123456');
        $login('203.0.113.5', '[masked:14 chars #ffffffffffff]');   // a different password of the same length
        $login('203.0.113.6', '[masked:9 chars]');                  // from before fingerprints
        $login('203.0.113.7', '[masked:9 chars]');

        $props = $this->signIn()->get('/credentials')->viewData('page')['props'];

        $this->assertSame([
            ['password' => $secret, 'attempts' => 3, 'addresses' => 2],
            ['password' => '123456', 'attempts' => 2, 'addresses' => 2],
        ], $props['mostTried']);
        $tried = collect($props['attempts'])->pluck('tried', 'password');
        $this->assertSame(['attempts' => 3, 'addresses' => 2], $tried[$secret]);
        $this->assertNull($tried['[masked:14 chars #ffffffffffff]']);   // tried once
        $this->assertNull($tried['[masked:9 chars]']);                  // lengths alone can't tell passwords apart
    }
}
