<?php

namespace App\Services;

use App\Models\Event;
use Illuminate\Support\Carbon;

/** The overview's events-per-hour chart. */
class TrafficChart
{
    /** The chart's ranges, in hours. */
    public const RANGES = ['24h' => 24, '7d' => 168];

    public const DEFAULT_RANGE = '24h';

    public function __construct(private Settings $settings) {}

    /** The range asked for, or the default when it isn't one of RANGES. */
    public static function range(string $asked): string
    {
        return array_key_exists($asked, self::RANGES) ? $asked : self::DEFAULT_RANGE;
    }

    /**
     * Events bucketed by hour over the range, zero-filled so the chart shows
     * quiet hours as gaps rather than collapsing them, and counted by kind so
     * each bar can show what its hour was made of. Buckets are UTC hours;
     * each is labelled with its start in the display zone, so a half-hour
     * zone reads 07:30, 08:30, ... `from` and `to` are the bucket's bounds in
     * the display zone, as the stream filter's `time` reads them, so clicking
     * a bar can filter the stream to exactly that hour. Over 7 days the label
     * carries the weekday too.
     *
     * @return list<array{hour: string, from: string, to: string, count: int, kinds: array<string, int>}>
     */
    public function byHour(string $range): array
    {
        $hours = self::RANGES[$range];
        $counts = [];
        Event::where('occurred_at', '>=', now()->subHours($hours - 1)->startOfHour())
            ->selectRaw("strftime('%Y-%m-%dT%H', occurred_at) AS bucket, ".Event::kindSql().' AS kind, COUNT(*) AS count')
            ->groupBy('bucket', 'kind')
            ->get()
            ->each(function ($row) use (&$counts): void {
                $counts[$row->bucket][$row->kind] = (int) $row->count;
            });
        $none = array_fill_keys(Event::KINDS, 0);

        $bars = [];
        foreach (range($hours - 1, 0) as $hoursAgo) {
            $bucket = now()->subHours($hoursAgo)->format('Y-m-d\TH');
            $utc = Carbon::createFromFormat('!Y-m-d\TH', $bucket, 'UTC');
            $start = $this->settings->local($utc);
            $kinds = [...$none, ...($counts[$bucket] ?? [])];
            $bars[] = [
                'hour' => $start->format($hours > 24 ? 'D H:i' : 'H:i'),
                'from' => $start->format('Y-m-d H:i'),
                'to' => $this->settings->local($utc->copy()->addHour())->format('Y-m-d H:i'),
                'count' => array_sum($kinds),
                'kinds' => $kinds,
            ];
        }

        return $bars;
    }
}
