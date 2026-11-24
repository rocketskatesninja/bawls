<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Services\Glossary;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/** The plain-English tooltips: complete, and honest about what bans. */
class GlossaryTest extends TestCase
{
    use RefreshDatabase;

    public function test_signed_in_pages_get_it_and_the_sign_in_page_does_not(): void
    {
        $this->assertNull($this->get('/test-console-slug')->assertOk()->viewData('page')['props']['glossary']);

        $props = $this->signIn()->get('/')->viewData('page')['props'];
        $this->assertSame(app(Glossary::class)->all(), $props['glossary']);
    }

    public function test_every_signature_and_alert_rule_is_explained(): void
    {
        $glossary = app(Glossary::class)->all();

        $signatures = [...Event::EXPLOIT_SIGNATURES, ...Event::SCAN_SIGNATURES, ...Event::HARMLESS_SIGNATURES, 'login'];
        foreach ($signatures as $signature) {
            $this->assertNotEmpty($glossary['signatures'][$signature]['text'] ?? null, "no meaning for signature {$signature}");
        }
        foreach (array_keys(config('bawls.rules')) as $rule) {
            $this->assertNotEmpty($glossary['rules'][$rule]['text'] ?? null, "no meaning for rule {$rule}");
        }
        foreach (['exploit', 'login', 'scan', 'page', 'firewall', 'other'] as $kind) {
            $this->assertNotEmpty($glossary['kinds'][$kind]['text'] ?? null, "no meaning for kind {$kind}");
        }
    }

    public function test_rule_text_carries_the_configured_thresholds(): void
    {
        config(['bawls.rules.web_scan.distinct_paths' => 30, 'bawls.rules.web_scan.window' => 600]);

        $this->assertSame(
            'One address asked the decoy for 30 or more different pages within 10 minutes.',
            app(Glossary::class)->all()['rules']['web_scan']['text'],
        );
    }

    public function test_only_what_actually_bans_says_it_bans(): void
    {
        config(['bawls.ban.enabled' => true, 'bawls.ban.rules' => 'web_exploit']);
        $glossary = app(Glossary::class)->all();
        foreach (Event::EXPLOIT_SIGNATURES as $signature) {
            $this->assertTrue($glossary['signatures'][$signature]['bans'], $signature);
        }
        $this->assertFalse($glossary['signatures']['dirbust']['bans']);
        $this->assertFalse($glossary['signatures']['login']['bans']);
        $this->assertTrue($glossary['rules']['web_exploit']['bans']);
        $this->assertFalse($glossary['rules']['web_scan']['bans']);
        $this->assertTrue($glossary['kinds']['exploit']['bans']);

        // With banning off, nothing claims to ban.
        config(['bawls.ban.enabled' => false]);
        $off = app(Glossary::class)->all();
        $this->assertFalse($off['signatures']['sqli']['bans']);
        $this->assertFalse($off['rules']['web_exploit']['bans']);
    }
}
