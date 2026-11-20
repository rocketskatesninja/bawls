<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ip_intel', function (Blueprint $table): void {
            // City-level coordinates for the dossier map (MaxMind GeoLite2-City).
            $table->decimal('latitude', 10, 7)->nullable()->after('city');
            $table->decimal('longitude', 10, 7)->nullable()->after('latitude');
            // GreyNoise classification: benign | malicious | unknown.
            $table->string('greynoise_class', 16)->nullable()->after('abuse_reports');
            // Shodan InternetDB open ports for this host.
            $table->json('open_ports')->nullable()->after('greynoise_class');
            // Known Tor exit node (from InternetDB tags).
            $table->boolean('tor_exit')->nullable()->after('open_ports');
            // Abuse contact from the IP's RDAP record.
            $table->string('abuse_contact', 190)->nullable()->after('tor_exit');
        });
    }

    public function down(): void
    {
        Schema::table('ip_intel', function (Blueprint $table): void {
            $table->dropColumn([
                'latitude', 'longitude', 'greynoise_class',
                'open_ports', 'tor_exit', 'abuse_contact',
            ]);
        });
    }
};
