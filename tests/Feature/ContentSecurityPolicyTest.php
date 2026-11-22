<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ContentSecurityPolicyTest extends TestCase
{
    use RefreshDatabase;

    private function assertStrictPolicy(?string $policy): void
    {
        $this->assertNotNull($policy, 'Content-Security-Policy header missing');

        foreach (["default-src 'self'", "script-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"] as $directive) {
            $this->assertStringContainsString($directive, $policy);
        }
        // Scripts may never be inline or eval'd: that's the point of the policy.
        $this->assertStringNotContainsString("script-src 'self' 'unsafe", $policy);
    }

    public function test_the_sign_in_page_sends_the_policy(): void
    {
        $this->assertStrictPolicy(
            $this->get('/test-console-slug')->assertOk()->headers->get('Content-Security-Policy')
        );
    }

    public function test_console_pages_send_the_policy(): void
    {
        $this->actingAs(User::factory()->create());

        foreach (['/', '/ip', '/credentials'] as $path) {
            $this->assertStrictPolicy($this->get($path)->assertOk()->headers->get('Content-Security-Policy'));
        }
    }
}
