<?php

namespace Tests;

use App\Models\User;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /** Files a test made that are removed when it ends. */
    private array $temporaryFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->temporaryFiles as $file) {
            @unlink($file);
        }
        $this->temporaryFiles = [];

        parent::tearDown();
    }

    /** Act as a signed-in console user. */
    protected function signIn(): static
    {
        return $this->actingAs(User::factory()->create());
    }

    /**
     * Stand in for fail2ban's current bans: the copy the installer's
     * bawls-bans timer writes for the console (App\Services\Bans), in a file
     * of this test's own. Each ban is "address or block" => [banned at,
     * expires at], in the server's local time as fail2ban prints it;
     * $utcOffset says what that zone is. Returns the file's path.
     *
     * @param  array<string, array{0: string, 1: string}>  $bans
     */
    protected function fakeBans(array $bans, string $utcOffset = '+0000', bool $enabled = true): string
    {
        $path = tempnam(sys_get_temp_dir(), 'bawls-bans-');
        $this->temporaryFiles[] = $path;

        $lines = ["# utc-offset {$utcOffset}"];
        foreach ($bans as $address => [$bannedAt, $expiresAt]) {
            $lines[] = "{$address} \t{$bannedAt} + 604800 = {$expiresAt}";
        }
        file_put_contents($path, implode("\n", $lines)."\n");
        config(['bawls.ban.enabled' => $enabled, 'bawls.ban.export' => $path]);

        return $path;
    }
}
