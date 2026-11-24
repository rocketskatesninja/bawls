<?php

namespace Tests\Unit;

use App\Services\Network;
use PHPUnit\Framework\TestCase;

class NetworkTest extends TestCase
{
    public function test_ipv4_ranges(): void
    {
        $this->assertTrue(Network::inCidr('203.0.113.9', '203.0.113.0/24'));
        $this->assertFalse(Network::inCidr('203.0.114.9', '203.0.113.0/24'));
        $this->assertTrue(Network::inCidr('172.20.1.1', '172.16.0.0/12'));
        $this->assertFalse(Network::inCidr('172.32.1.1', '172.16.0.0/12'));
        $this->assertTrue(Network::inCidr('8.8.8.8', '0.0.0.0/0'));
        $this->assertTrue(Network::inCidr('203.0.113.9', '203.0.113.9'));      // a bare address is itself
        $this->assertFalse(Network::inCidr('203.0.113.10', '203.0.113.9'));
    }

    public function test_ipv6_ranges(): void
    {
        $this->assertTrue(Network::inCidr('2001:db8:1::5', '2001:db8:1::/48'));
        $this->assertFalse(Network::inCidr('2001:db8:2::5', '2001:db8:1::/48'));
        $this->assertTrue(Network::inCidr('fd12:3456::1', 'fc00::/7'));
        $this->assertTrue(Network::inCidr('fe80::1', 'fe80::/10'));
        $this->assertFalse(Network::inCidr('fec0::1', 'fe80::/10'));
        $this->assertTrue(Network::inCidr('2001:DB8::1', '2001:db8:0:0::1'));   // same address, written differently
    }

    public function test_families_never_cross_and_junk_never_matches(): void
    {
        $this->assertFalse(Network::inCidr('::1', '0.0.0.0/0'));
        $this->assertFalse(Network::inCidr('127.0.0.1', '::/0'));
        $this->assertFalse(Network::inCidr('not-an-ip', '10.0.0.0/8'));
        $this->assertFalse(Network::inCidr('10.0.0.1', 'nonsense'));
        $this->assertFalse(Network::inCidr('10.0.0.1', '10.0.0.0/99'));
    }

    public function test_what_gets_banned_for_an_address(): void
    {
        $this->assertSame('203.0.113.9', Network::block('203.0.113.9'));
        $this->assertSame('2001:db8:1:2::/64', Network::block('2001:db8:1:2:aaaa:bbbb:cccc:7'));
        $this->assertSame('2001:db8::/64', Network::block('2001:DB8::1'));
        $this->assertSame('junk', Network::block('junk'));
    }
}
