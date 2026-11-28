<?php

namespace App\Models;

use Database\Factories\AlertFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;

class Alert extends Model
{
    /** @use HasFactory<AlertFactory> */
    use HasFactory;

    protected $fillable = [
        'rule', 'severity', 'title', 'src_ip', 'dst_ip', 'host',
        'first_seen_at', 'last_seen_at', 'event_count', 'details', 'status',
    ];

    /**
     * Alerts nobody has acknowledged or resolved yet.
     *
     * @param  Builder<Alert>  $query
     */
    public function scopeOpen(Builder $query): void
    {
        $query->where('status', 'open');
    }

    /**
     * Put an address's hidden and dismissed alerts back among the open ones:
     * per rule, its hidden alert, or failing that its latest dismissed one.
     * A rule that already has an open alert is left alone, so there is never
     * more than one live alert per rule and address. Returns how many reopened.
     */
    public static function reopenFor(string $ip): int
    {
        $reopened = 0;

        foreach (self::where('src_ip', $ip)->orderByDesc('last_seen_at')->get()->groupBy('rule') as $alerts) {
            if ($alerts->contains('status', 'open')) {
                continue;
            }
            ($alerts->firstWhere('status', 'acked') ?? $alerts->first())->update(['status' => 'open']);
            $reopened++;
        }

        return $reopened;
    }

    /**
     * Which of these addresses have something reopenFor() would reopen.
     *
     * @param  Collection<int, string>  $ips
     * @return Collection<string, true>
     */
    public static function reopenable(Collection $ips): Collection
    {
        return self::whereIn('src_ip', $ips->unique()->values())
            ->selectRaw("src_ip, rule, SUM(status = 'open') AS open_count")
            ->groupBy('src_ip', 'rule')
            ->get()
            ->filter(fn (self $row): bool => (int) $row->open_count === 0)
            ->mapWithKeys(fn (self $row): array => [$row->src_ip => true]);
    }

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'details' => 'array',
        ];
    }
}
