<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('events', function (Blueprint $table) {
            // An event's signature lives in its JSON (raw.signature). Reading
            // it from there for every row made "sig == sqli" scan the whole
            // table; this exposes it as a column SQLite can index. Virtual:
            // nothing is stored twice, and the sensors' payload is untouched.
            $table->string('signature', 32)->virtualAs("json_extract(raw, '$.signature')")->nullable();
            $table->index(['signature', 'occurred_at']);
        });

        Schema::table('alerts', function (Blueprint $table) {
            // "Did this address ever raise an alert?" (pruning, the dossier,
            // the blocklist) had no index that starts with the address.
            $table->index('src_ip');
        });

        Schema::table('sensors', function (Blueprint $table) {
            // A token identifies exactly one sensor.
            $table->unique('token_hash');
        });
    }

    public function down(): void
    {
        Schema::table('sensors', fn (Blueprint $table) => $table->dropUnique(['token_hash']));
        Schema::table('alerts', fn (Blueprint $table) => $table->dropIndex(['src_ip']));
        Schema::table('events', function (Blueprint $table) {
            $table->dropIndex(['signature', 'occurred_at']);
            $table->dropColumn('signature');
        });
    }
};
