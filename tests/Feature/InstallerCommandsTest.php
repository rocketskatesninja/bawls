<?php

namespace Tests\Feature;

use App\Console\Commands\UserCreate;
use App\Models\Sensor;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * install.sh drives these commands without a terminal: it reads the sensor
 * token from stdout and hands the console password over in the environment.
 */
class InstallerCommandsTest extends TestCase
{
    use RefreshDatabase;

    protected function tearDown(): void
    {
        putenv(UserCreate::PASSWORD_ENV);
        parent::tearDown();
    }

    public function test_token_only_prints_just_the_token_and_registers_it(): void
    {
        Artisan::call('bawls:sensor', ['name' => 'box-decoy', '--kind' => 'honeypot', '--token-only' => true]);
        $token = trim(Artisan::output());

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9]{48}$/', $token);
        $this->assertSame(hash('sha256', $token), Sensor::where('name', 'box-decoy')->value('token_hash'));
    }

    public function test_rotate_reissues_the_token_of_an_existing_sensor(): void
    {
        Artisan::call('bawls:sensor', ['name' => 'box-ufw', '--token-only' => true]);
        $first = trim(Artisan::output());

        Artisan::call('bawls:sensor', ['name' => 'box-ufw', '--rotate' => true, '--token-only' => true]);
        $second = trim(Artisan::output());

        $this->assertNotSame($first, $second);
        $this->assertSame(1, Sensor::where('name', 'box-ufw')->count());
        $this->assertSame(hash('sha256', $second), Sensor::where('name', 'box-ufw')->value('token_hash'));
    }

    public function test_the_password_can_come_from_the_environment(): void
    {
        putenv(UserCreate::PASSWORD_ENV.'=correct-horse-42-battery');

        $this->artisan('bawls:user', ['email' => 'admin@example.test'])->assertSuccessful();

        $this->assertTrue(Hash::check('correct-horse-42-battery', User::where('email', 'admin@example.test')->value('password')));
    }

    public function test_keep_leaves_an_existing_user_alone(): void
    {
        User::factory()->create(['email' => 'admin@example.test', 'password' => 'original-password-1']);
        putenv(UserCreate::PASSWORD_ENV.'=replacement-password-2');

        $this->artisan('bawls:user', ['email' => 'admin@example.test', '--keep' => true])
            ->expectsOutputToContain('left unchanged')
            ->assertSuccessful();

        $this->assertTrue(Hash::check('original-password-1', User::where('email', 'admin@example.test')->value('password')));
    }

    public function test_keep_still_creates_a_missing_user(): void
    {
        putenv(UserCreate::PASSWORD_ENV.'=correct-horse-42-battery');

        $this->artisan('bawls:user', ['email' => 'admin@example.test', '--keep' => true])->assertSuccessful();

        $this->assertDatabaseHas('users', ['email' => 'admin@example.test']);
    }
}
