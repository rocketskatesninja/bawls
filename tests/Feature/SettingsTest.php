<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Models\Sensor;
use App\Models\Setting;
use App\Services\Settings;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class SettingsTest extends TestCase
{
    use RefreshDatabase;

    private function decoyHit(string $at, array $raw = ['path' => '/wp-login.php', 'signature' => 'benign']): Event
    {
        return Event::factory()->create([
            'sensor_id' => Sensor::factory()->create()->id,
            'occurred_at' => Carbon::parse($at, 'UTC'),
            'source' => 'honeypot_http', 'action' => 'probed', 'src_ip' => '203.0.113.9', 'raw' => $raw,
        ]);
    }

    public function test_the_settings_page_is_not_reachable_anonymously(): void
    {
        $this->get('/settings')->assertNotFound();
        $this->put('/settings', ['timezone' => 'UTC', 'accent' => '#39ff8b'])->assertNotFound();
        $this->assertSame(0, Setting::count());
    }

    public function test_a_fresh_install_uses_the_defaults(): void
    {
        $this->signIn()
            ->get('/settings')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Settings', false)
                ->where('values', ['timezone' => 'UTC', 'accent' => '#39ff8b', 'text_size' => '100'])
                ->where('settings.text_size', '100')
                ->has('textSizes', 3)
                ->where('settings.timezone', 'UTC')
                ->where('settings.accent_dim', '#208f4e')
                ->has('zones.America')
            );
    }

    public function test_saving_stores_the_values_and_every_page_gets_them(): void
    {
        $this->signIn();

        $this->from('/settings')
            ->put('/settings', ['timezone' => 'America/New_York', 'accent' => '#B18CFF', 'text_size' => '115'])
            ->assertRedirect('/settings')
            ->assertSessionHasNoErrors();

        $this->assertSame('#b18cff', Setting::find('accent')->value);
        $this->assertSame('115', Setting::find('text_size')->value);

        $this->get('/')
            ->assertInertia(fn (Assert $page) => $page
                ->where('settings.timezone', 'America/New_York')
                ->where('settings.accent', '#b18cff')
                ->where('settings.accent_dim', '#634e8f')
                ->where('settings.text_size', '115')
            )
            // The first paint is already in the new colour and size.
            ->assertSee('--color-phosphor: #b18cff', false)
            ->assertSee('font-size: 115%', false);
    }

    public function test_bad_values_are_refused(): void
    {
        $this->signIn();

        $this->put('/settings', ['timezone' => 'Mars/Olympus_Mons', 'accent' => 'green'])
            ->assertSessionHasErrors(['timezone', 'accent']);
        $this->put('/settings', ['timezone' => 'UTC', 'accent' => '#39ff8b;}body{display:none', 'text_size' => '100'])
            ->assertSessionHasErrors('accent');
        $this->put('/settings', ['timezone' => 'UTC', 'accent' => '#39ff8b', 'text_size' => '200'])
            ->assertSessionHasErrors('text_size');
        $this->put('/settings', ['timezone' => 'UTC', 'accent' => '#39ff8b', 'text_size' => '100%;}body{display:none'])
            ->assertSessionHasErrors('text_size');

        $this->assertSame(0, Setting::count());
    }

    public function test_an_accent_too_dark_to_read_is_refused(): void
    {
        $this->signIn();

        $this->put('/settings', ['timezone' => 'UTC', 'accent' => '#1a2a8c', 'text_size' => '100'])
            ->assertSessionHasErrors('accent');

        $this->assertLessThan(Settings::MIN_CONTRAST, Settings::contrast('#1a2a8c'));
        $this->assertGreaterThan(Settings::MIN_CONTRAST, Settings::contrast('#39ff8b'));
    }

    public function test_a_stored_text_size_that_is_not_on_the_list_is_never_printed(): void
    {
        // Only the Settings form writes this, and it validates; this guards the
        // page root, which prints the value into a style attribute.
        Setting::create(['key' => 'text_size', 'value' => '100%;}body{display:none']);

        $this->signIn()
            ->get('/')
            ->assertInertia(fn (Assert $page) => $page->where('settings.text_size', '100'))
            ->assertSee('font-size: 100%', false)
            ->assertDontSee('display:none', false);
    }

    public function test_event_times_are_shown_in_the_chosen_zone(): void
    {
        $this->signIn();
        Carbon::setTestNow('2026-01-15 12:30:00');
        $this->decoyHit('2026-01-15 12:00:05', ['path' => '/wp-login.php', 'signature' => 'login', 'login_attempt' => true]);

        app(Settings::class)->update(['timezone' => 'America/New_York']);

        $this->get('/')
            ->assertInertia(fn (Assert $page) => $page
                ->where('stream.rows.0.at', '07:00:05')
                ->where('settings.timezone_label', 'EST')
            );
        $this->get('/credentials')
            ->assertInertia(fn (Assert $page) => $page->where('attempts.0.at', 'Jan 15 07:00:05'));
        $this->get('/ip/203.0.113.9')
            ->assertInertia(fn (Assert $page) => $page->where('selected.timeline.0.at', 'Jan 15 07:00:05'));
    }

    public function test_chart_hours_are_labelled_in_the_chosen_zone(): void
    {
        $this->signIn();
        Carbon::setTestNow('2026-01-15 12:30:00');
        app(Settings::class)->update(['timezone' => 'Asia/Kolkata']);   // UTC+05:30

        $traffic = $this->get('/')->viewData('page')['props']['traffic'];

        // The newest bucket is the 12:00 UTC hour: 17:30 in Kolkata.
        $this->assertSame('17:30', end($traffic)['hour']);
        $this->assertSame('18:30', $traffic[0]['hour']);
    }

    public function test_pages_still_load_before_the_settings_table_exists(): void
    {
        Schema::drop('settings');

        $this->signIn()
            ->get('/')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page->where('settings.accent', '#39ff8b'));
    }
}
