<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // Nothing by default: a console must never gain an account with a known
        // password. Create yours with `php artisan bawls:user`; for screenshot
        // data on an empty database, run `php artisan db:seed --class=DemoSeeder`.
    }
}
