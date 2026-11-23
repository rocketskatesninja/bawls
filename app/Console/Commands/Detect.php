<?php

namespace App\Console\Commands;

use App\Services\AlertDetector;
use Illuminate\Console\Command;

class Detect extends Command
{
    protected $signature = 'bawls:detect';

    protected $description = 'Scan recent events for attack patterns and record alerts';

    public function handle(AlertDetector $detector): int
    {
        $count = $detector->run();

        $this->info($count === 0
            ? 'No detections in the current windows.'
            : "Recorded {$count} detection(s).");

        return self::SUCCESS;
    }
}
