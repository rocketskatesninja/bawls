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
    /** IPv4 CIDR membership. Non-IPv4 addresses never match. */
    public static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, '32');

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = $bits === '0' ? 0 : -1 << (32 - (int) $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
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
