<?php

namespace App\Services;

use App\Models\Event;
use Illuminate\Database\Eloquent\Builder;

/**
 * The event stream under its display filter (App\Services\DisplayFilter):
 * the one place that turns filter text into a query, shared by the overview's
 * paged list and the export, so both always show the same events.
 */
class EventStream
{
    /** Rows a page: 25, 50 or 100 as chosen in the console, within these limits. */
    public const PER_PAGE = 50;

    public const MIN_PER_PAGE = 5;

    public const MAX_PER_PAGE = 100;

    public function __construct(private Settings $settings) {}

    /**
     * Every event the filter matches, newest first.
     *
     * @return Builder<Event>
     *
     * @throws DisplayFilterError when the filter doesn't parse
     */
    public function query(string $filter): Builder
    {
        $query = Event::query();
        DisplayFilter::parse(trim($filter))?->apply($query, $this->settings->timezone());

        return $query->latest('occurred_at')->latest('id');
    }

    /**
     * One page of the stream; a page past the end shows the last one. A
     * filter that doesn't parse comes back as `error`, with no rows (the page
     * keeps showing its last good ones).
     *
     * @return array{filter: string, rows: list<array<string, mixed>>, matched: int, page: int, per: int, pages: int, error: array{message: string, at: int}|null}
     */
    public function page(string $filter, int $page, int $per): array
    {
        $filter = trim($filter);
        $per = max(self::MIN_PER_PAGE, min(self::MAX_PER_PAGE, $per));
        $stream = ['filter' => $filter, 'rows' => [], 'matched' => 0, 'page' => 1, 'per' => $per, 'pages' => 1, 'error' => null];
        try {
            $query = $this->query($filter);
        } catch (DisplayFilterError $error) {
            return [...$stream, 'error' => $error->toArray()];
        }

        $matched = (clone $query)->reorder()->count();
        $pages = max(1, (int) ceil($matched / $per));
        $page = max(1, min($page, $pages));

        return [
            ...$stream,
            'matched' => $matched,
            'page' => $page,
            'pages' => $pages,
            'rows' => $query->offset(($page - 1) * $per)->limit($per)->get()->map($this->row(...))->all(),
        ];
    }

    /**
     * @return array{id: int, at: string, src: string, src_ip: string, dst: string, proto: string, info: string, kind: string}
     */
    private function row(Event $event): array
    {
        return [
            'id' => $event->id,
            'at' => $this->settings->stamp($event->occurred_at, dateOnlyIfOlder: true),
            'src' => $event->sourceAddress(),
            'src_ip' => $event->src_ip,
            'dst' => $event->destinationAddress(),
            'proto' => $event->protocolLabel(),
            'info' => $event->summary(),
            'kind' => $event->kind(),
        ];
    }
}
