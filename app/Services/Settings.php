<?php

namespace App\Services;

use App\Models\Setting;
use Carbon\CarbonInterface;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Database\QueryException;

/**
 * Console preferences, set from the Settings page.
 *
 * The defaults live here, so a fresh install needs no rows: the table only
 * holds what someone changed. Times are always stored in UTC; the time zone
 * setting only changes how the console shows them.
 *
 * Bound as a scoped singleton, so the table is read once per request.
 */
class Settings
{
    /** @var array{timezone: string, accent: string} */
    public const DEFAULTS = [
        'timezone' => 'UTC',
        'accent' => '#39ff8b',
    ];

    /** The console's background (--color-void in app.css). */
    public const BACKGROUND = '#070b09';

    /** WCAG AA for text: a darker accent is hard to read on the background. */
    public const MIN_CONTRAST = 4.5;

    /** How much of the accent its dim shade keeps (--color-phosphor-dim). */
    private const DIM = 0.56;

    /** @var array{timezone: string, accent: string}|null */
    private ?array $values = null;

    /**
     * @return array{timezone: string, accent: string}
     */
    public function all(): array
    {
        if ($this->values === null) {
            try {
                $stored = Setting::query()->pluck('value', 'key')->all();
            } catch (QueryException) {
                // Not migrated yet (mid-upgrade): show the defaults rather than
                // fail every page, the sign-in page included.
                $stored = [];
            }

            $this->values = array_merge(self::DEFAULTS, array_intersect_key($stored, self::DEFAULTS));
        }

        return $this->values;
    }

    /**
     * Save the given settings; keys this class doesn't know are ignored.
     * Callers validate first (see SettingsController).
     *
     * @param  array<string, string>  $values
     */
    public function update(array $values): void
    {
        foreach (array_intersect_key($values, self::DEFAULTS) as $key => $value) {
            Setting::query()->updateOrCreate(['key' => $key], ['value' => $value]);
        }

        $this->values = null;
    }

    public function timezone(): string
    {
        return $this->all()['timezone'];
    }

    public function accent(): string
    {
        return $this->all()['accent'];
    }

    /** The accent's dim shade, for borders and glows. */
    public function accentDim(): string
    {
        $channels = array_map(
            fn (int $channel): int => (int) round($channel * self::DIM),
            sscanf($this->accent(), '#%02x%02x%02x'),
        );

        return sprintf('#%02x%02x%02x', ...$channels);
    }

    /** A stored (UTC) time, moved into the zone the console shows times in. */
    public function local(CarbonInterface $time): CarbonInterface
    {
        return $time->copy()->setTimezone($this->timezone());
    }

    /** The display zone's short name right now: "EST", "IST", "UTC". */
    public function timezoneLabel(): string
    {
        return now($this->timezone())->format('T');
    }

    /**
     * Every zone PHP knows, grouped by region for the Settings picker, each
     * with its current UTC offset.
     *
     * @return array<string, array<int, array{id: string, label: string, offset: string}>>
     */
    public static function zoneChoices(): array
    {
        $now = new DateTimeImmutable('now');
        $groups = [];

        foreach (DateTimeZone::listIdentifiers() as $id) {
            if (! str_contains($id, '/')) {
                continue;   // UTC, offered on its own above the regions
            }

            [$region, $place] = explode('/', $id, 2);
            $seconds = (new DateTimeZone($id))->getOffset($now);

            $groups[$region][] = [
                'id' => $id,
                'label' => str_replace(['_', '/'], [' ', ' / '], $place),
                'offset' => sprintf('%s%02d:%02d', $seconds < 0 ? '−' : '+', intdiv(abs($seconds), 3600), intdiv(abs($seconds) % 3600, 60)),
            ];
        }

        return $groups;
    }

    /** WCAG contrast ratio of a colour against the console's background (1 to 21). */
    public static function contrast(string $hex): float
    {
        $lighter = max(self::luminance($hex), self::luminance(self::BACKGROUND));
        $darker = min(self::luminance($hex), self::luminance(self::BACKGROUND));

        return ($lighter + 0.05) / ($darker + 0.05);
    }

    private static function luminance(string $hex): float
    {
        $linear = array_map(function (int $channel): float {
            $c = $channel / 255;

            return $c <= 0.04045 ? $c / 12.92 : (($c + 0.055) / 1.055) ** 2.4;
        }, sscanf($hex, '#%02x%02x%02x'));

        return 0.2126 * $linear[0] + 0.7152 * $linear[1] + 0.0722 * $linear[2];
    }
}
