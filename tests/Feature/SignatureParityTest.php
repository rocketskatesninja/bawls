<?php

namespace Tests\Feature;

use App\Models\Event;
use App\Services\Glossary;
use App\Services\UserAgent;
use Illuminate\Support\Facades\Process;
use Tests\TestCase;

/**
 * The sensors (Python) label requests; the console (PHP) colours, explains
 * and bans by those labels. Each side keeps its own copy of the lists, and
 * this asks the sensors' code for theirs so a change to one side can't pass
 * without the other.
 */
class SignatureParityTest extends TestCase
{
    private const SENSOR_LISTS = <<<'PY'
        import json, sys
        sys.path.insert(0, sys.argv[1])
        import signatures
        json.dump({
            "signatures": list(signatures.SIGNATURES),
            "exploit": sorted(signatures.EXPLOIT_SIGNATURES),
            "scanners": signatures.SCANNER_UA_RE.pattern.split("|"),
        }, sys.stdout)
        PY;

    /**
     * @return array{signatures: list<string>, exploit: list<string>, scanners: list<string>}
     */
    private function sensorLists(): array
    {
        $result = Process::run(['python3', '-I', '-c', self::SENSOR_LISTS, base_path('sensors')]);
        $this->assertTrue($result->successful(), $result->errorOutput());

        return json_decode($result->output(), true);
    }

    public function test_both_sides_know_the_same_signatures(): void
    {
        $sensor = $this->sensorLists();

        $this->assertSame($sensor['signatures'], Event::SIGNATURES);
        $this->assertSame($sensor['exploit'], collect(Event::EXPLOIT_SIGNATURES)->sort()->values()->all());
    }

    public function test_every_signature_is_grouped_and_explained(): void
    {
        $grouped = [...Event::EXPLOIT_SIGNATURES, 'login', ...Event::SCAN_SIGNATURES, ...Event::HARMLESS_SIGNATURES];
        $this->assertEqualsCanonicalizing(Event::SIGNATURES, $grouped);

        $this->assertEqualsCanonicalizing(Event::SIGNATURES, array_keys(app(Glossary::class)->all()['signatures']));
    }

    public function test_the_dossier_calls_every_scanner_the_sensors_know_automated(): void
    {
        foreach ($this->sensorLists()['scanners'] as $tool) {
            $this->assertTrue(UserAgent::summarize("{$tool}/1.0")['bot'], "UserAgent::TOOLS is missing {$tool}");
        }
    }
}
