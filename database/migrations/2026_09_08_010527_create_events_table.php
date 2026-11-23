<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('events', function (Blueprint $table) {
            $table->id();
            $table->timestamp('occurred_at')->index();
            $table->foreignId('sensor_id')->constrained()->cascadeOnDelete();
            $table->string('host', 64);                 // reporting box
            $table->string('source', 24);               // ufw_block | ebpf_connect | ebpf_accept | mirror_flow | sshd_auth
            $table->string('direction', 3);             // in | out
            $table->string('proto', 8);                 // tcp | udp | icmp | igmp | other
            $table->string('src_ip', 45);
            $table->unsignedInteger('src_port')->nullable();
            $table->string('dst_ip', 45);
            $table->unsignedInteger('dst_port')->nullable();
            $table->string('iface', 24)->nullable();
            $table->string('action', 12);               // blocked | allowed | accepted | failed
            // eBPF-only process attribution
            $table->unsignedInteger('pid')->nullable();
            $table->string('process', 128)->nullable();
            // flow-only counters
            $table->unsignedBigInteger('bytes')->nullable();
            $table->unsignedBigInteger('packets')->nullable();
            $table->json('raw')->nullable();

            // Hot paths: "what did this IP do", "what happened recently",
            // and the detector's per-source sliding windows.
            $table->index(['src_ip', 'occurred_at']);
            $table->index(['source', 'occurred_at']);
            $table->index(['dst_port', 'occurred_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('events');
    }
};
