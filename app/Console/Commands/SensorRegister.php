<?php

namespace App\Console\Commands;

use App\Models\Sensor;
use Illuminate\Console\Command;
use Illuminate\Support\Str;

class SensorRegister extends Command
{
    protected $signature = 'bawls:sensor
                            {name : Unique sensor name, e.g. web1-ufw}
                            {--host= : Box the sensor runs on (default: the name prefix)}
                            {--kind=ufw : ufw | honeypot | sites}
                            {--rotate : Reissue the token for an existing sensor}
                            {--token-only : Print just the token, for install scripts}';

    protected $description = 'Register a sensor and print its ingest token (shown once)';

    public function handle(): int
    {
        $name = $this->argument('name');
        $host = $this->option('host') ?: Str::before($name, '-');
        $kind = $this->option('kind');

        $existing = Sensor::where('name', $name)->first();

        if ($existing && ! $this->option('rotate')) {
            $this->error("Sensor [{$name}] already exists. Use --rotate to reissue its token.");

            return self::FAILURE;
        }

        $token = Str::random(48);

        $sensor = $existing ?? new Sensor(['name' => $name]);
        $sensor->fill([
            'host' => $host,
            'kind' => $kind,
            'token_hash' => hash('sha256', $token),
            'enabled' => true,
        ])->save();

        if ($this->option('token-only')) {
            $this->line($token);

            return self::SUCCESS;
        }

        $this->newLine();
        $this->info($existing ? "Token rotated for [{$name}]." : "Sensor [{$name}] registered.");
        $this->line("  host: {$host}   kind: {$kind}");
        $this->newLine();
        $this->comment('  Token (shown once — copy it now):');
        $this->line("  {$token}");
        $this->newLine();

        return self::SUCCESS;
    }
}
