<?php

namespace App\Services;

/**
 * The on/off switch for the disclosed browser-fingerprint test at
 * /browser-check. The decoy serves that page only while the flag file exists,
 * so flipping this toggles the feature at runtime with no restart. Default off.
 */
class BrowserCheck
{
    /**
     * Kept in its own directory: that directory is the only part of the app
     * (besides its own code) the sandboxed decoy can see.
     */
    public static function flagPath(): string
    {
        return storage_path('app/decoy/browser_check.enabled');
    }

    public static function enabled(): bool
    {
        return is_file(self::flagPath());
    }

    public static function enable(): void
    {
        $path = self::flagPath();
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0775, true);
        }
        file_put_contents($path, "on\n");
        // World-readable so the decoy's own unprivileged user can stat it.
        @chmod($path, 0644);
    }

    public static function disable(): void
    {
        if (is_file(self::flagPath())) {
            unlink(self::flagPath());
        }
    }
}
