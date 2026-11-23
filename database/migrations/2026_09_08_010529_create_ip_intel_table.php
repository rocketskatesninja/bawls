<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('ip_intel', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->unique();
            $table->boolean('is_private')->default(false);
            $table->string('country', 2)->nullable();
            $table->string('city', 64)->nullable();
            $table->unsignedInteger('asn')->nullable();
            $table->string('as_org', 128)->nullable();
            $table->string('rdns', 253)->nullable();
            $table->unsignedTinyInteger('abuse_score')->nullable();   // AbuseIPDB 0-100
            $table->unsignedInteger('abuse_reports')->nullable();
            $table->timestamp('checked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('ip_intel');
    }
};
