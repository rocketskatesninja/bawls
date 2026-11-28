<?php

namespace Tests\Feature;

use App\Services\BrowserCheck;
use Illuminate\Support\Facades\File;
use Tests\TestCase;

class BrowserCheckToggleTest extends TestCase
{
    private string $storage;

    protected function setUp(): void
    {
        parent::setUp();
        // A storage folder of its own: the real flag (storage/app/decoy) belongs
        // to whoever runs this console, and a test run mustn't switch it off.
        $this->storage = sys_get_temp_dir().'/bawls-test-'.bin2hex(random_bytes(6));
        $this->app->useStoragePath($this->storage);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->storage);
        parent::tearDown();
    }

    public function test_the_fingerprint_test_is_off_by_default(): void
    {
        $this->assertFalse(BrowserCheck::enabled());
    }

    public function test_the_command_toggles_it_on_and_off(): void
    {
        $this->artisan('bawls:browser-check on')->assertSuccessful();
        $this->assertTrue(BrowserCheck::enabled());

        $this->artisan('bawls:browser-check off')->assertSuccessful();
        $this->assertFalse(BrowserCheck::enabled());
    }

    public function test_an_unknown_state_is_rejected(): void
    {
        $this->artisan('bawls:browser-check sideways')->assertFailed();
    }
}
