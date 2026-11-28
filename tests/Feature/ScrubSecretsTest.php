<?php

namespace Tests\Feature;

use App\Models\Event;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** bawls:scrub-secrets masks credentials in events stored before the sensors did. */
class ScrubSecretsTest extends TestCase
{
    use RefreshDatabase;

    private const SECRET = 'Zq7-real-Passw0rd!';

    /**
     * @param  array<string, mixed>  $raw
     */
    private function event(array $raw): Event
    {
        // Exactly $raw: these tests compare what is stored before and after.
        return Event::factory()->decoy()->create(['raw' => $raw]);
    }

    public function test_it_masks_every_place_a_credential_was_left(): void
    {
        $old = $this->event([
            'method' => 'POST', 'path' => '/wp-login.php', 'signature' => 'login', 'login_attempt' => true,
            'query' => 'redirect_to=%2F&password='.self::SECRET,
            'referer' => 'https://example.com/login?token='.self::SECRET.'&next=/',
            'form' => ['log' => 'bob', 'pwd' => '[masked:18 chars]'],
            'body_excerpt' => 'log=bob&pwd='.self::SECRET,
            'headers' => [
                'Authorization' => 'Basic '.self::SECRET, 'Cookie' => 'session='.self::SECRET.'; theme=dark',
                'X-Api-Key' => self::SECRET, 'User-Agent' => 'curl/8',
                'Referer' => 'https://example.com/login?token='.self::SECRET.'&next=/',
            ],
        ]);

        $this->artisan('bawls:scrub-secrets')->expectsOutputToContain('Masked credentials in 1 event(s).')->assertSuccessful();

        $raw = $old->fresh()->raw;
        $this->assertStringNotContainsString(self::SECRET, json_encode($raw));
        $this->assertSame('log=bob&pwd=%5Bmasked%3A18+chars%5D', $raw['body_excerpt']);
        $this->assertSame('redirect_to=%2F&password=%5Bmasked%3A18+chars%5D', $raw['query']);
        $this->assertSame('Basic [masked:18 chars]', $raw['headers']['Authorization']);
        $this->assertSame('session=[masked]; theme=[masked]', $raw['headers']['Cookie']);
        $this->assertSame('[masked:18 chars]', $raw['headers']['X-Api-Key']);
        $this->assertSame('curl/8', $raw['headers']['User-Agent']);
    }

    public function test_it_leaves_ordinary_events_and_common_passwords_alone_and_is_safe_to_repeat(): void
    {
        $probe = $this->event(['method' => 'GET', 'path' => '/', 'query' => 'url=.env&x=%2e%2e', 'signature' => 'dirbust', 'headers' => ['Accept' => '*/*']]);
        $common = $this->event(['method' => 'GET', 'path' => '/login', 'query' => 'user=admin&password=123456', 'signature' => 'benign']);
        $before = [$probe->raw, $common->raw];

        $this->artisan('bawls:scrub-secrets')->expectsOutputToContain('in 0 event(s)')->assertSuccessful();
        $this->assertSame($before, [$probe->fresh()->raw, $common->fresh()->raw]);
    }

    public function test_a_dry_run_counts_and_changes_nothing(): void
    {
        $old = $this->event(['method' => 'POST', 'path' => '/login', 'signature' => 'login', 'form' => ['pwd' => '[masked:18 chars]'], 'body_excerpt' => 'pwd='.self::SECRET]);

        $this->artisan('bawls:scrub-secrets --dry-run')->expectsOutputToContain('Would mask credentials in 1 event(s).')->assertSuccessful();
        $this->assertStringContainsString(self::SECRET, $old->fresh()->raw['body_excerpt']);

        $this->artisan('bawls:scrub-secrets')->assertSuccessful();
        $this->artisan('bawls:scrub-secrets')->expectsOutputToContain('in 0 event(s)')->assertSuccessful();
    }
}
