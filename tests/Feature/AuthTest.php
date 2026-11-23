<?php

namespace Tests\Feature;

use App\Models\Sensor;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Tests\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'correct-horse-battery-9';

    private const EMAIL = 'watch@example.test';

    private function user(): User
    {
        return User::factory()->create([
            'email' => self::EMAIL,
            'password' => Hash::make(self::PASSWORD),
        ]);
    }

    public function test_the_dashboard_is_not_reachable_anonymously(): void
    {
        // 404, not a redirect to a login: nothing may hint a console exists.
        $this->get('/')->assertNotFound();
    }

    public function test_the_default_login_path_is_hidden(): void
    {
        $this->get('/login')->assertNotFound();
        $this->post('/login', ['email' => self::EMAIL, 'password' => self::PASSWORD])
            ->assertNotFound();
    }

    public function test_the_login_page_renders_at_the_secret_path(): void
    {
        $this->get(route('login'))->assertOk();
    }

    public function test_valid_credentials_sign_in(): void
    {
        $user = $this->user();

        $this->post(route('login'), ['email' => $user->email, 'password' => self::PASSWORD])
            ->assertRedirect(route('overview'));

        $this->assertAuthenticatedAs($user);
    }

    public function test_invalid_credentials_are_rejected(): void
    {
        $user = $this->user();

        $this->post(route('login'), ['email' => $user->email, 'password' => 'wrong'])
            ->assertSessionHasErrors('email');

        $this->assertGuest();
    }

    public function test_the_error_does_not_reveal_whether_the_account_exists(): void
    {
        $this->user();

        $unknown = $this->post(route('login'), ['email' => 'nobody@example.test', 'password' => 'wrong'])
            ->assertSessionHasErrors('email')
            ->getSession()->get('errors')->first('email');

        $wrongPassword = $this->post(route('login'), ['email' => self::EMAIL, 'password' => 'wrong'])
            ->assertSessionHasErrors('email')
            ->getSession()->get('errors')->first('email');

        $this->assertSame($unknown, $wrongPassword);
    }

    public function test_repeated_failures_are_throttled(): void
    {
        RateLimiter::clear('login:'.self::EMAIL.'|127.0.0.1');
        $this->user();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->post(route('login'), ['email' => self::EMAIL, 'password' => 'wrong']);
        }

        $this->post(route('login'), ['email' => self::EMAIL, 'password' => 'wrong'])
            ->assertSessionHasErrors('email');

        $errors = session('errors')->first('email');
        $this->assertStringContainsString('Too many attempts', $errors);

        // The correct password must not get through while locked out.
        $this->post(route('login'), ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $this->assertGuest();
    }

    public function test_an_authenticated_user_reaches_the_dashboard(): void
    {
        $this->actingAs($this->user())->get('/')->assertOk();
    }

    public function test_sign_out_ends_the_session(): void
    {
        $this->actingAs($this->user())
            ->post('/logout')
            ->assertRedirect(route('login'));

        $this->assertGuest();
    }

    public function test_there_is_no_registration_route(): void
    {
        $this->post('/register', [
            'email' => 'intruder@example.com',
            'password' => 'password-12345',
        ])->assertNotFound();

        $this->assertSame(0, User::where('email', 'intruder@example.com')->count());
    }

    public function test_sensor_ingest_still_works_without_a_session(): void
    {
        // Sensors authenticate with their own bearer token; adding session
        // auth to the console must not lock the agents out.
        $token = 'sensor-token-0000000000000000000000000000';
        Sensor::factory()->withToken($token)->create();

        $this->withToken($token)->postJson('/api/ingest', ['events' => [[
            'occurred_at' => '2026-09-08T01:00:00Z',
            'source' => 'ufw_block',
            'direction' => 'in',
            'proto' => 'tcp',
            'src_ip' => '203.0.113.9',
            'dst_ip' => '10.0.0.101',
            'dst_port' => 22,
            'action' => 'blocked',
        ]]])->assertStatus(201);
    }
}
