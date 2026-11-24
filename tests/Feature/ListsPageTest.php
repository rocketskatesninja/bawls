<?php

namespace Tests\Feature;

use App\Models\Alert;
use App\Models\IpIntel;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ListsPageTest extends TestCase
{
    use RefreshDatabase;

    private string $export;

    protected function setUp(): void
    {
        parent::setUp();
        Carbon::setTestNow('2026-11-20 12:00:00');
        $this->export = storage_path('framework/testing/banned.txt');
        @mkdir(dirname($this->export), 0777, true);
        @unlink($this->export);
        config([
            'bawls.ban.enabled' => true,
            'bawls.ban.export' => $this->export,
            'bawls.ban.never_block' => '198.51.100.9',
        ]);
    }

    protected function tearDown(): void
    {
        @unlink($this->export);
        parent::tearDown();
    }

    /** Write the copy the bawls-bans timer makes, dated like it was just made. */
    private function writeExport(string $contents, ?Carbon $at = null): void
    {
        file_put_contents($this->export, $contents);
        touch($this->export, ($at ?? now())->getTimestamp());
    }

    private function alert(string $ip, string $rule = 'web_exploit', int $severity = 5): Alert
    {
        return Alert::factory()->create(['rule' => $rule, 'severity' => $severity, 'title' => "{$rule} from {$ip}", 'src_ip' => $ip]);
    }

    public function test_it_shows_fail2bans_bans_with_why_and_where(): void
    {
        // fail2ban prints the server's local time; this server runs 2 hours ahead of UTC.
        $this->writeExport(implode("\n", [
            '# utc-offset +0200',
            "203.0.113.9 \t2026-11-18 07:54:00 + 604800 = 2026-11-25 07:54:00",
            "203.0.113.20 \t2026-11-19 14:00:00 + 604800 = 2026-11-26 14:00:00",
            "not-an-ip \t2026-11-19 14:00:00 + 604800 = 2026-11-26 14:00:00",
            'Status for the jail: bawls',
        ])."\n");
        $this->alert('203.0.113.9', 'web_scan', 3);
        $this->alert('203.0.113.9');
        IpIntel::create(['ip' => '203.0.113.9', 'country' => 'NL', 'as_org' => 'Example Hosting', 'checked_at' => now()]);

        $this->signIn()->get('/lists')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Lists', false)
                ->where('bans.enabled', true)
                ->where('bans.stale', false)
                ->where('bans.as_of', 'Nov 20 12:00:00')
                ->has('bans.rows', 2)
                // Newest first; the junk lines are skipped.
                ->where('bans.rows.0.ip', '203.0.113.20')
                ->where('bans.rows.0.rule', null)
                ->where('bans.rows.1.ip', '203.0.113.9')
                ->where('bans.rows.1.banned_at', 'Nov 18 05:54')
                ->where('bans.rows.1.expires_at', 'Nov 25 05:54')
                ->where('bans.rows.1.expires_in', '4d 17h from now')
                // Raw times (UTC seconds) so the page can sort by date.
                ->where('bans.rows.1.banned_ts', Carbon::parse('2026-11-18 05:54:00', 'UTC')->getTimestamp())
                ->where('bans.rows.1.expires_ts', Carbon::parse('2026-11-25 05:54:00', 'UTC')->getTimestamp())
                // Why: the worst alert, the exploit attempt.
                ->where('bans.rows.1.rule', 'web_exploit')
                ->where('bans.rows.1.severity', 5)
                ->where('bans.rows.1.country', 'NL')
                ->where('bans.rows.1.org', 'Example Hosting'));
    }

    public function test_it_says_when_there_is_no_copy_or_it_is_stale(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->get('/lists')->assertInertia(fn (Assert $page) => $page
            ->where('bans.as_of', null)
            ->where('bans.stale', false)
            ->has('bans.rows', 0));

        $this->writeExport("# utc-offset +0000\n", now()->subMinutes(6));
        $this->actingAs($user)->get('/lists')->assertInertia(fn (Assert $page) => $page
            ->where('bans.stale', true));
    }

    public function test_it_says_when_the_ban_feed_is_off(): void
    {
        config(['bawls.ban.enabled' => false]);

        $this->signIn()->get('/lists')
            ->assertInertia(fn (Assert $page) => $page->where('bans.enabled', false));
    }

    public function test_the_blocklist_tab_groups_alerts_by_address_and_marks_bans(): void
    {
        $this->writeExport("# utc-offset +0000\n203.0.113.9 \t2026-11-20 11:00:00 + 604800 = 2026-11-27 11:00:00\n");
        $this->alert('203.0.113.9');
        $this->alert('203.0.113.9', 'web_scan', 3);
        $this->alert('203.0.113.50', 'web_scan', 3);
        $this->alert('10.0.0.5');     // private: never listed
        $this->alert('198.51.100.9');    // never-block: never listed

        $this->signIn()->get('/lists')
            ->assertInertia(fn (Assert $page) => $page
                ->has('blocklist', 2)
                ->where('blocklist.0.ip', '203.0.113.9')
                ->where('blocklist.0.rules', ['web_exploit', 'web_scan'])
                ->where('blocklist.0.alerts', 2)
                ->where('blocklist.0.severity', 5)
                ->where('blocklist.0.banned', true)
                ->where('blocklist.1.ip', '203.0.113.50')
                ->where('blocklist.1.banned', false));
    }

    public function test_the_plain_blocklist_downloads_for_signed_in_users_only(): void
    {
        $this->alert('203.0.113.9');

        $this->get('/blocklist.txt')->assertNotFound();

        $this->signIn()->get('/blocklist.txt')
            ->assertOk()
            ->assertHeader('Content-Disposition', 'attachment; filename="bawls-blocklist.txt"')
            ->assertSee('203.0.113.9');
    }

    public function test_a_banned_ipv6_block_is_listed_as_the_block_and_covers_its_addresses(): void
    {
        $this->alert('2001:db8:1:2:aaaa::7');
        $this->alert('2001:db8:1:2:bbbb::9', 'web_scan', 3);   // a second address in the same block
        $this->alert('2001:db8:9:9::1', 'web_scan', 3);        // another block: not banned
        $this->writeExport("# utc-offset +0000\n2001:db8:1:2::/64 \t2026-11-20 11:00:00 + 604800 = 2026-11-27 11:00:00\n");

        $props = $this->signIn()->get('/lists')->viewData('page')['props'];

        $ban = $props['bans']['rows'][0];
        $this->assertSame('2001:db8:1:2::/64', $ban['ip']);
        $this->assertContains($ban['address'], ['2001:db8:1:2:aaaa::7', '2001:db8:1:2:bbbb::9']);
        $this->assertNotNull($ban['rule']);

        $banned = collect($props['blocklist'])->pluck('banned', 'ip');
        $this->assertTrue($banned['2001:db8:1:2:aaaa::7']);
        $this->assertTrue($banned['2001:db8:1:2:bbbb::9']);
        $this->assertFalse($banned['2001:db8:9:9::1']);

        // The plain blocklist names each block once.
        $text = $this->get('/blocklist.txt')->assertOk()->getContent();
        $this->assertSame(1, substr_count($text, '2001:db8:1:2::/64'));
        $this->assertStringNotContainsString('aaaa', $text);
    }
}
