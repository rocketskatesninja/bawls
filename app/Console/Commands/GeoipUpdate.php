<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use PharData;
use RuntimeException;
use Throwable;

class GeoipUpdate extends Command
{
    protected $signature = 'bawls:geoip-update';

    protected $description = 'Download the latest MaxMind GeoLite2 City and ASN databases';

    /** @var array<int, string> */
    private const EDITIONS = ['GeoLite2-City', 'GeoLite2-ASN'];

    public function handle(): int
    {
        $key = config('services.maxmind.license_key');
        if (! $key) {
            // Not a failure: enrichment just skips geo/ASN until a key is set.
            $this->warn('MAXMIND_LICENSE_KEY is not set — skipping GeoIP update.');

            return self::SUCCESS;
        }

        $dir = (string) config('services.maxmind.db_path');
        if (! is_dir($dir) && ! mkdir($dir, 0775, true) && ! is_dir($dir)) {
            $this->error("Cannot create {$dir}");

            return self::FAILURE;
        }

        foreach (self::EDITIONS as $edition) {
            try {
                $this->download($edition, $key, $dir);
                $this->info("Updated {$edition}.");
            } catch (Throwable $error) {
                $this->error("Failed {$edition}: {$error->getMessage()}");

                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }

    private function download(string $edition, string $key, string $dir): void
    {
        $archive = sys_get_temp_dir().'/geoip_'.$edition.'_'.uniqid().'.tar.gz';
        $extractDir = $archive.'.d';

        try {
            $response = Http::timeout(120)->withOptions(['sink' => $archive])->get(
                'https://download.maxmind.com/app/geoip_download',
                ['edition_id' => $edition, 'license_key' => $key, 'suffix' => 'tar.gz'],
            );
            if (! $response->ok()) {
                throw new RuntimeException("download HTTP {$response->status()}");
            }

            mkdir($extractDir, 0775, true);
            (new PharData($archive))->extractTo($extractDir, null, true);

            $mmdb = $this->findMmdb($extractDir);
            if (! $mmdb) {
                throw new RuntimeException('no .mmdb in archive');
            }

            rename($mmdb, rtrim($dir, '/')."/{$edition}.mmdb");
        } finally {
            @unlink($archive);
            $this->removeDir($extractDir);
        }
    }

    private function findMmdb(string $dir): ?string
    {
        foreach (glob($dir.'/*/*.mmdb') ?: [] as $path) {
            return $path;
        }
        foreach (glob($dir.'/*.mmdb') ?: [] as $path) {
            return $path;
        }

        return null;
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }
        foreach (glob($dir.'/*') ?: [] as $path) {
            is_dir($path) ? $this->removeDir($path) : @unlink($path);
        }
        @rmdir($dir);
    }
}
