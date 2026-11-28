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

    public function test_one_table_lists_alerted_addresses_with_their_bans(): void
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
        $this->alert('203.0.113.50', 'web_scan', 3);
        $this->alert('10.0.0.5');        // private: never listed
        $this->alert('198.51.100.9');    // never-block: never listed
        IpIntel::create(['ip' => '203.0.113.9', 'country' => 'NL', 'as_org' => 'Example Hosting', 'checked_at' => now()]);

        $this->signIn()->get('/lists')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('Lists', false)
                ->where('bans', ['enabled' => true, 'as_of' => 'Nov 20 12:00:00', 'stale' => false])
                ->has('rows', 3)
                // Alerted addresses, worst first.
                ->where('rows.0.ip', '203.0.113.9')
                ->where('rows.0.rules', ['web_exploit', 'web_scan'])
                ->where('rows.0.alerts', 2)
                ->where('rows.0.severity', 5)
                ->where('rows.0.country', 'NL')
                ->where('rows.0.org', 'Example Hosting')
                ->where('rows.0.ban.block', null)
                ->where('rows.0.ban.banned_at', 'Nov 18 05:54')
                ->where('rows.0.ban.expires_at', 'Nov 25 05:54')
                ->where('rows.0.ban.expires_in', '4d 17h from now')
                // Raw time (UTC seconds) so the page can sort by date.
                ->where('rows.0.ban.expires_ts', Carbon::parse('2026-11-25 05:54:00', 'UTC')->getTimestamp())
                ->where('rows.1.ip', '203.0.113.50')
                ->where('rows.1.ban', null)
                // A ban with no alert behind it still gets a row; the junk line is skipped.
                ->where('rows.2.ip', '203.0.113.20')
                ->where('rows.2.rules', [])
                ->where('rows.2.severity', null)
                ->where('rows.2.dossier', true)
                ->where('rows.2.reopen', false)
                ->where('rows.2.ban.expires_at', 'Nov 26 12:00'));
    }

    public function test_it_says_when_there_is_no_copy_or_it_is_stale(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->get('/lists')->assertInertia(fn (Assert $page) => $page
            ->where('bans.as_of', null)
            ->where('bans.stale', false)
            ->has('rows', 0));

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

    public function test_the_plain_blocklist_downloads_for_signed_in_users_only(): void
    {
        $this->alert('203.0.113.9');

        $this->get('/blocklist.txt')->assertNotFound();

        $this->signIn()->get('/blocklist.txt')
            ->assertOk()
            ->assertHeader('Content-Disposition', 'attachment; filename="bawls-blocklist.txt"')
            ->assertSee('203.0.113.9');
    }

    public function test_a_banned_ipv6_block_marks_each_of_its_addresses_and_is_not_a_row_of_its_own(): void
    {
        $this->alert('2001:db8:1:2:aaaa::7');
        $this->alert('2001:db8:1:2:bbbb::9', 'web_scan', 3);   // a second address in the same block
        $this->alert('2001:db8:9:9::1', 'web_scan', 3);        // another block: not banned
        $this->writeExport(implode("\n", [
            '# utc-offset +0000',
            "2001:db8:1:2::/64 \t2026-11-20 11:00:00 + 604800 = 2026-11-27 11:00:00",
            "2001:db8:7:7::/64 \t2026-11-20 11:00:00 + 604800 = 2026-11-27 11:00:00",   // no alert in it
        ])."\n");

        $rows = collect($this->signIn()->get('/lists')->viewData('page')['props']['rows'])->keyBy('ip');

        $this->assertSame('2001:db8:1:2::/64', $rows['2001:db8:1:2:aaaa::7']['ban']['block']);
        $this->assertSame('2001:db8:1:2::/64', $rows['2001:db8:1:2:bbbb::9']['ban']['block']);
        $this->assertNull($rows['2001:db8:9:9::1']['ban']);
        $this->assertArrayNotHasKey('2001:db8:1:2::/64', $rows->all());

        // A banned block with no alerted address in it is listed as the block, without a dossier.
        $this->assertFalse($rows['2001:db8:7:7::/64']['dossier']);
        $this->assertNull($rows['2001:db8:7:7::/64']['ban']['block']);
        $this->assertCount(4, $rows);

        // The plain blocklist names each block once.
        $text = $this->get('/blocklist.txt')->assertOk()->getContent();
        $this->assertSame(1, substr_count($text, '2001:db8:1:2::/64'));
        $this->assertStringNotContainsString('aaaa', $text);
    }

    public function test_a_row_can_reopen_its_hidden_or_dismissed_alerts(): void
    {
        $hidden = $this->alert('203.0.113.9');
        $hidden->update(['status' => 'acked']);
        $older = $this->alert('203.0.113.10');
        $older->update(['status' => 'resolved', 'last_seen_at' => now()->subDay()]);
        $newer = $this->alert('203.0.113.10');
        $newer->update(['status' => 'resolved']);
        $scan = $this->alert('203.0.113.10', 'port_scan', 3);   // still open: left alone
        $this->alert('203.0.113.11');

        $this->post('/alerts/reopen', ['ip' => '203.0.113.9'])->assertNotFound();

        $user = User::factory()->create();
        $this->actingAs($user)->get('/lists')->assertInertia(fn (Assert $page) => $page
            ->where('rows', fn ($rows): bool => collect($rows)->pluck('reopen', 'ip')->sortKeys()->all() === [
                '203.0.113.10' => true, '203.0.113.11' => false, '203.0.113.9' => true,
            ]));

        $this->actingAs($user)->post('/alerts/reopen', ['ip' => 'nope'])->assertSessionHasErrors('ip');
        $this->actingAs($user)->post('/alerts/reopen', ['ip' => '203.0.113.9'])->assertRedirect();
        $this->actingAs($user)->post('/alerts/reopen', ['ip' => '203.0.113.10'])->assertRedirect();

        $this->assertSame('open', $hidden->fresh()->status);
        $this->assertSame(['resolved', 'open', 'open'], [$older->fresh()->status, $newer->fresh()->status, $scan->fresh()->status]);
        $this->assertSame(0, Alert::reopenFor('203.0.113.10'), 'nothing left to reopen');
    }
}
