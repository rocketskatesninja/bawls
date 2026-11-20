<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('sensors', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();          // e.g. "web1-ufw"
            $table->string('host');                     // the machine it runs on, e.g. web1
            $table->string('kind');                     // ufw | ebpf | mirror
            $table->string('token_hash');               // hash of the ingest token
            $table->timestamp('last_seen_at')->nullable();
            $table->unsignedBigInteger('events_received')->default(0);
            $table->boolean('enabled')->default(true);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('sensors');
    }
};
