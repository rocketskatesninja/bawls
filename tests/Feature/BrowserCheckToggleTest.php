<?php

namespace Tests\Feature;

use App\Services\BrowserCheck;
use Tests\TestCase;

class BrowserCheckToggleTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        BrowserCheck::disable();
    }

    protected function tearDown(): void
    {
        BrowserCheck::disable();
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
