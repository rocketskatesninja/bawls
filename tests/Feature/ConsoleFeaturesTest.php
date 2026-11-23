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
        return Alert::create([
            'rule' => 'web_exploit', 'severity' => 5, 'title' => 'x', 'src_ip' => $ip,
            'host' => 'web1', 'first_seen_at' => now(), 'last_seen_at' => now(),
            'event_count' => 1, 'status' => $status,
        ]);
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

        $this->actingAs(User::factory()->create())->get('/blocklist.txt')
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

        $this->actingAs(User::factory()->create())->get('/credentials')
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

        $this->actingAs(User::factory()->create())->get('/credentials')
            ->assertInertia(fn (Assert $p) => $p->component('Credentials', false)
                ->has('attempts', 2)                                      // the /contact post is not a login
                ->where('attempts.0.username', "admin' or 1=1--")
                ->where('attempts.0.attack', 'sqli')
                ->where('attempts.1.username', 'root')                   // phpMyAdmin field names
                ->where('attempts.1.password', 'toor')
                ->where('attempts.1.attack', null));
    }
}
