<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('alerts', function (Blueprint $table) {
            $table->id();
            $table->string('rule', 32);                 // a rule in App\Services\AlertDetector::RULES
            $table->unsignedTinyInteger('severity');    // 1 info .. 5 critical
            $table->string('title');
            $table->string('src_ip', 45)->nullable();
            $table->string('dst_ip', 45)->nullable();
            $table->string('host', 64);
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->unsignedInteger('event_count')->default(1);
            $table->json('details')->nullable();        // ports hit, rates, sample events
            $table->string('status', 12)->default('open'); // open | acked | resolved
            $table->timestamps();

            // The overview reads open alerts newest-first; the detector keeps
            // one unresolved alert per (rule, src_ip).
            $table->index(['status', 'last_seen_at']);
            $table->index(['rule', 'src_ip', 'last_seen_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('alerts');
    }
};
