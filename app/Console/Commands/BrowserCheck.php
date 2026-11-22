<?php

namespace App\Console\Commands;

use App\Services\BrowserCheck as Flag;
use Illuminate\Console\Command;

class BrowserCheck extends Command
{
    protected $signature = 'bawls:browser-check {state? : on | off | status}';

    protected $description = 'Toggle the disclosed browser-fingerprint test served at /browser-check';

    public function handle(): int
    {
        $state = strtolower((string) ($this->argument('state') ?: 'status'));

        if ($state === 'on') {
            Flag::enable();
        } elseif ($state === 'off') {
            Flag::disable();
        } elseif ($state !== 'status') {
            $this->error('Usage: bawls:browser-check {on|off|status}');

            return self::FAILURE;
        }

        $this->info(Flag::enabled()
            ? '/browser-check is ON — serving the disclosed fingerprint test.'
            : '/browser-check is off — the path is invisible.');

        return self::SUCCESS;
    }
}
