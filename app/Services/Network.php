<?php

namespace App\Services;

/**
 * Address classification shared by the ingest filter and the detector.
 *
 * Both need the same answer to "is this address one of ours", and having
 * two copies of that logic is how a filter and a detection rule quietly
 * start disagreeing about what counts as internal.
 */
class Network
{
    /**
     * CIDR membership, IPv4 or IPv6 ("203.0.113.0/24", "fd00::/8"; a bare
     * address is a /32 or /128). An address never matches a range of the
     * other family, and anything unparseable matches nothing.
     */
    public static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        $address = @inet_pton($ip);
        $network = @inet_pton($subnet);
        if ($address === false || $network === false || strlen($address) !== strlen($network)) {
            return false;
        }

        $bits = $bits === null ? strlen($network) * 8 : (int) $bits;
        if ($bits < 0 || $bits > strlen($network) * 8) {
            return false;
        }
        $whole = intdiv($bits, 8);
        if (substr($address, 0, $whole) !== substr($network, 0, $whole)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = 0xFF << (8 - $rest) & 0xFF;

        return (ord($address[$whole]) & $mask) === (ord($network[$whole]) & $mask);
    }

    /** An IPv6 block: what one customer or server is normally given, and can rotate through freely. */
    public const IPV6_BLOCK_BITS = 64;

    /**
     * What gets banned for an address: an IPv4 address itself, or the whole
     * /64 an IPv6 address sits in ("2001:db8:1:2::/64"), since banning one
     * IPv6 address only makes its owner pick the next of their 2^64.
     */
    public static function block(string $ip): string
    {
        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return $ip;
        }
        $bytes = intdiv(self::IPV6_BLOCK_BITS, 8);

        return inet_ntop(substr($packed, 0, $bytes).str_repeat("\0", 16 - $bytes)).'/'.self::IPV6_BLOCK_BITS;
    }

    /**
     * @param  array<int, string>  $cidrs
     */
    public static function inAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::inCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /** True when the address sits inside a configured local network. */
    public static function isInternal(string $ip): bool
    {
        return self::inAny($ip, config('bawls.local_networks', []));
    }

    /** True for multicast and broadcast destinations. */
    public static function isMulticast(string $ip): bool
    {
        return self::inAny($ip, config('bawls.multicast_networks', []));
    }

    /**
     * True when neither end of the conversation leaves the local network.
     *
     * This is the "not worth storing" case for a home network: two of your
     * own machines talking to each other, or a host talking to itself over
     * its LAN address rather than loopback.
     */
    public static function isPurelyInternal(string $src, string $dst): bool
    {
        return self::isInternal($src) && self::isInternal($dst);
    }
}
