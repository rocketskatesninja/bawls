<?php

namespace App\Console\Commands;

use App\Services\Blocklist;
use Illuminate\Console\Command;

class BlocklistCommand extends Command
{
    protected $signature = 'bawls:blocklist';

    protected $description = 'Write the current attacker blocklist to storage/app/blocklist.txt';

    public function handle(): int
    {
        $path = Blocklist::writeFile();
        $this->info('Wrote '.Blocklist::ips()->count().' IP(s) to '.$path);

        return self::SUCCESS;
    }
}
