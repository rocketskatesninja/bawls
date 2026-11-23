<?php

namespace App\Http\Controllers;

use App\Models\Event;
use App\Models\Sensor;
use App\Services\DisplayFilter;
use App\Services\DisplayFilterError;
use App\Services\Settings;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * The stream's Export: every event its display filter matches, newest first,
 * like Wireshark's "Export Packet Dissections" with "All packets, Displayed".
 * That is all of them, not only the rows on screen (the stream shows 1,000 at
 * most). CSV carries the stream's columns with the full date; JSON carries
 * each whole event, its request details included.
 */
class StreamExportController extends Controller
{
    /** Events read per query, so no read holds SQLite's lock for long. */
    private const BATCH = 500;

    public function __construct(private Settings $settings) {}

    public function __invoke(Request $request): StreamedResponse
    {
        $format = $request->string('format')->toString() === 'json' ? 'json' : 'csv';

        try {
            $filter = DisplayFilter::parse(trim($request->string('f')->toString()));
        } catch (DisplayFilterError $error) {
            abort(422, $error->getMessage());
        }

        $query = Event::query()->latest('occurred_at')->latest('id');
        $filter?->apply($query, $this->settings->timezone());
        $ids = $query->pluck('id');

        $name = 'bawls-events-'.$this->settings->local(now())->format('Y-m-d-His').".{$format}";
        $type = $format === 'json' ? 'application/json' : 'text/csv; charset=UTF-8';

        return response()->streamDownload(
            fn () => $format === 'json' ? $this->json($ids) : $this->csv($ids),
            $name,
            ['Content-Type' => $type, 'Cache-Control' => 'no-store'],
        );
    }

    /**
     * @param  Collection<int, int>  $ids
     */
    private function csv(Collection $ids): void
    {
        $out = fopen('php://output', 'w');
        fputcsv($out, ['No.', 'Time ('.$this->settings->timezone().')', 'Source', 'Destination', 'Protocol', 'Info'], escape: '');
        foreach ($this->events($ids) as $event) {
            fputcsv($out, array_map($this->cell(...), [
                $event->id,
                $this->settings->local($event->occurred_at)->format('Y-m-d H:i:s'),
                $event->src_ip.($event->src_port ? ':'.$event->src_port : ''),
                $event->dst_ip.($event->dst_port ? ':'.$event->dst_port : ''),
                $event->protocolLabel(),
                $event->summary(),
            ]), escape: '');
        }
        fclose($out);
    }

    /**
     * One JSON array, one event per line.
     *
     * @param  Collection<int, int>  $ids
     */
    private function json(Collection $ids): void
    {
        $sensors = Sensor::pluck('name', 'id');
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        echo '[';
        $first = true;
        foreach ($this->events($ids) as $event) {
            echo ($first ? "\n" : ",\n").json_encode([
                ...$event->toArray(),
                'sensor' => $sensors[$event->sensor_id] ?? null,
                'kind' => $event->kind(),
                'info' => $event->summary(),
            ], $flags);
            $first = false;
        }
        echo "\n]\n";
    }

    /**
     * The events in the order of $ids, read a batch at a time. One that was
     * pruned since the ids were listed is skipped.
     *
     * @param  Collection<int, int>  $ids
     * @return iterable<Event>
     */
    private function events(Collection $ids): iterable
    {
        foreach ($ids->chunk(self::BATCH) as $batch) {
            $events = Event::whereIn('id', $batch->all())->get()->keyBy('id');
            foreach ($batch as $id) {
                if ($events->has($id)) {
                    yield $events[$id];
                }
            }
        }
    }

    /**
     * A spreadsheet runs a cell that starts with = + - or @ as a formula, and
     * attackers choose what lands in Info (the path, the method), so those
     * cells get a leading apostrophe and open as plain text.
     */
    private function cell(string|int $value): string|int
    {
        return is_string($value) && preg_match('/^[=+\-@\t\r]/', $value) ? "'".$value : $value;
    }
}
