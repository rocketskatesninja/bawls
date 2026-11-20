<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Event;
use App\Models\Sensor;
use App\Services\Network;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

class IngestController extends Controller
{
    /** Sensors batch their events, so one request carries many. */
    private const MAX_BATCH = 500;

    public function store(Request $request): JsonResponse
    {
        /** @var Sensor $sensor */
        $sensor = $request->attributes->get('sensor');

        $data = $request->validate([
            'events' => ['required', 'array', 'min:1', 'max:'.self::MAX_BATCH],
            'events.*.occurred_at' => ['required', 'date'],
            'events.*.source' => ['required', 'string', 'in:ufw_block,ebpf_connect,ebpf_accept,mirror_flow,sshd_auth,honeypot_http'],
            'events.*.direction' => ['required', 'string', 'in:in,out'],
            'events.*.proto' => ['required', 'string', 'max:8'],
            'events.*.src_ip' => ['required', 'ip'],
            'events.*.src_port' => ['nullable', 'integer', 'between:0,65535'],
            'events.*.dst_ip' => ['required', 'ip'],
            'events.*.dst_port' => ['nullable', 'integer', 'between:0,65535'],
            'events.*.iface' => ['nullable', 'string', 'max:24'],
            'events.*.action' => ['required', 'string', 'in:blocked,allowed,accepted,failed,probed'],
            'events.*.pid' => ['nullable', 'integer', 'min:0'],
            'events.*.process' => ['nullable', 'string', 'max:128'],
            'events.*.bytes' => ['nullable', 'integer', 'min:0'],
            'events.*.packets' => ['nullable', 'integer', 'min:0'],
            'events.*.raw' => ['nullable', 'array'],
        ]);

        $kept = array_values(array_filter($data['events'], $this->worthStoring(...)));
        $dropped = count($data['events']) - count($kept);

        $rows = array_map(fn (array $e): array => [
            'occurred_at' => Carbon::parse($e['occurred_at'])->utc(),
            'sensor_id' => $sensor->id,
            'host' => $sensor->host,
            'source' => $e['source'],
            'direction' => $e['direction'],
            'proto' => $e['proto'],
            'src_ip' => $e['src_ip'],
            'src_port' => $e['src_port'] ?? null,
            'dst_ip' => $e['dst_ip'],
            'dst_port' => $e['dst_port'] ?? null,
            'iface' => $e['iface'] ?? null,
            'action' => $e['action'],
            'pid' => $e['pid'] ?? null,
            'process' => $e['process'] ?? null,
            'bytes' => $e['bytes'] ?? null,
            'packets' => $e['packets'] ?? null,
            'raw' => isset($e['raw']) ? json_encode($e['raw']) : null,
        ], $kept);

        if ($rows !== []) {
            Event::insert($rows);
        }

        // last_seen_at is updated even when every event was filtered, so a
        // sensor reporting only noise still shows as alive rather than
        // appearing to have died. One atomic UPDATE, so batches arriving at
        // the same moment can't lose each other's counts.
        $sensor->increment('events_received', count($rows), ['last_seen_at' => now()]);

        return response()->json([
            'accepted' => count($rows),
            'dropped' => $dropped,
        ], 201);
    }

    /**
     * Decide whether an event is worth persisting.
     *
     * @param  array<string, mixed>  $event
     */
    private function worthStoring(array $event): bool
    {
        // A hit on the decoy is always worth keeping, including LAN-internal
        // test probes that the internal/multicast filters would otherwise drop.
        if (($event['source'] ?? null) === 'honeypot_http') {
            return true;
        }

        $store = config('bawls.store');

        if (($store['drop_multicast'] ?? false) && Network::isMulticast($event['dst_ip'])) {
            return false;
        }

        if (($store['drop_internal'] ?? false)
            && Network::isPurelyInternal($event['src_ip'], $event['dst_ip'])) {
            return false;
        }

        return true;
    }
}
