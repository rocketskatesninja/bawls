<?php

namespace Tests\Unit;

use App\Services\DisplayFilter;
use App\Services\DisplayFilterError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DisplayFilterSyntaxTest extends TestCase
{
    public function test_an_empty_filter_means_everything(): void
    {
        $this->assertNull(DisplayFilter::parse(''));
        $this->assertNull(DisplayFilter::parse("  \t "));
    }

    /** @return array<string, array{string}> */
    public static function validFilters(): array
    {
        return [
            'flag' => ['http'],
            'word operators' => ['not ufw and src eq 203.0.113.9 or port ge 1024'],
            'wireshark names' => ['ip.src == 192.0.2.77 && http.request.uri contains "id=" && tcp.dstport == 80'],
            'ipv6' => ['ip == 2001:db8::1'],
            'cidr' => ['src == 203.0.113.0/24 || src == 10.0.0.0/8'],
            'set with commas' => ['port in {22, 80, 443}'],
            'quoted escapes' => ['ua contains "say \\"hi\\""'],
            'unquoted time' => ['time >= 2026-11-20T14:00'],
            'nesting' => ['!(sig == benign) && (country in {CN RU} || asn == 64500)'],
            'no spaces' => ['src==203.0.113.9&&port!=22'],
        ];
    }

    #[DataProvider('validFilters')]
    public function test_it_parses(string $filter): void
    {
        $this->assertInstanceOf(DisplayFilter::class, DisplayFilter::parse($filter));
    }

    /** @return array<string, array{string, string, int}> */
    public static function invalidFilters(): array
    {
        return [
            'single =' => ['src = 203.0.113.9', 'Compare with ==', 4],
            'single &' => ['http & ufw', 'Join conditions with &&', 5],
            'unknown field' => ['foo == 1', 'Unknown field "foo"', 0],
            'bare field' => ['src', '"src" needs a comparison, like src == 203.0.113.9', 0],
            'flag with a comparison' => ['login == 1', '"login" is a flag', 6],
            'wrong operator' => ['path > 3', '"path" can\'t use >', 5],
            'not a number' => ['port == ssh', '"port" takes a whole number', 8],
            'odd range' => ['src == 203.0.113.0/20', 'isn\'t an address or a /8, /16, /24 or /32', 7],
            'not a time' => ['time > yesterday', 'isn\'t a time', 7],
            'unclosed paren' => ['(ufw || http', 'A "(" is never closed', 0],
            'unclosed quote' => ['path == "/wp', 'A quote is never closed', 8],
            'two conditions, no join' => ['ufw http', 'Unexpected "http"', 4],
            'dangling &&' => ['ufw &&', 'ends too soon', 6],
            'missing value' => ['port ==', 'A value is missing', 7],
            'empty set' => ['port in {}', 'A set holds 1 to 50 values', 8],
            'in without a set' => ['port in 22', '"in" takes a set', 8],
            'unclosed set' => ['port in {22 80', 'A "{" is never closed', 8],
            'stray symbol' => ['src == 1.2.3.4;', 'Unexpected ";"', 14],
        ];
    }

    #[DataProvider('invalidFilters')]
    public function test_it_explains_what_is_wrong_and_where(string $filter, string $message, int $position): void
    {
        try {
            DisplayFilter::parse($filter);
            $this->fail("\"{$filter}\" should not parse");
        } catch (DisplayFilterError $error) {
            $this->assertStringContainsString($message, $error->getMessage());
            $this->assertSame($position, $error->position);
        }
    }

    public function test_it_has_limits(): void
    {
        $tooLong = 'path contains "'.str_repeat('a', DisplayFilter::MAX_LENGTH).'"';
        $tooMany = implode('||', array_fill(0, DisplayFilter::MAX_TESTS + 1, 'ufw'));
        $tooDeep = str_repeat('!', DisplayFilter::MAX_DEPTH + 2).'ufw';

        foreach (['too long' => $tooLong, 'Too many conditions' => $tooMany, 'nested too deeply' => $tooDeep] as $message => $filter) {
            try {
                DisplayFilter::parse($filter);
                $this->fail("{$message}: should not parse");
            } catch (DisplayFilterError $error) {
                $this->assertStringContainsString($message, $error->getMessage());
            }
        }
    }
}
