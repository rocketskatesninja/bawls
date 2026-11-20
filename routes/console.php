<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('bawls:detect')->everyMinute()->withoutOverlapping();
Schedule::command('bawls:enrich')->everyFiveMinutes()->withoutOverlapping();
Schedule::command('bawls:blocklist')->hourly();
Schedule::command('bawls:prune')->dailyAt('03:30');
// MaxMind refreshes GeoLite2 on Tuesdays and Fridays; pull mid-week.
Schedule::command('bawls:geoip-update')->weeklyOn(3, '04:00');
