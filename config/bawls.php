<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Detection thresholds
    |--------------------------------------------------------------------------
    |
    | Each rule looks back over a window (seconds) and fires when a source
    | crosses its threshold. Tuned for a home network: deliberately loose
    | enough that ordinary traffic stays quiet, tight enough that a real
    | scan trips within a minute or two.
    |
    */

    'rules' => [

        'port_scan' => [
            'enabled' => true,
            'window' => 300,          // 5 minutes
            'distinct_ports' => 15,   // distinct dst ports on one host
            'severity' => 3,
        ],

        'host_sweep' => [
            'enabled' => true,
            'window' => 300,
            'distinct_hosts' => 10,   // distinct dst hosts from one source
            'severity' => 3,
        ],

        'flood' => [
            'enabled' => true,
            'window' => 60,
            'events' => 500,          // events from a single source per window
            'severity' => 4,
        ],

        'brute_force' => [
            'enabled' => true,
            'window' => 300,
            'attempts' => 10,
            'ports' => [22, 23, 3389, 445, 3306, 5432, 21],
            'severity' => 4,
        ],

        'web_exploit' => [
            'enabled' => true,
            'window' => 600,
            'signatures' => ['cve_probe', 'rce', 'sqli', 'traversal'],
            'severity' => 5,
        ],

        'web_scan' => [
            'enabled' => true,
            'window' => 300,
            'distinct_paths' => 12,   // distinct decoy paths from one source
            'severity' => 3,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | What gets stored
    |--------------------------------------------------------------------------
    |
    | Filters applied at ingest, before anything is written. On a home
    | network the overwhelming majority of events are the router's own
    | multicast chatter and machines talking to each other — neither of
    | which is an attack surface. Dropping them here keeps the database
    | about the traffic that crosses your boundary.
    |
    | Set either to false to store everything again; nothing else changes.
    |
    */

    'store' => [
        // Drop conversations where both ends are inside local_networks.
        'drop_internal' => env('BAWLS_DROP_INTERNAL', true),

        // Drop multicast and broadcast destinations (IGMP, SSDP, mDNS).
        'drop_multicast' => env('BAWLS_DROP_MULTICAST', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Local networks
    |--------------------------------------------------------------------------
    |
    | Addresses considered "ours". Defaults to the RFC1918 ranges plus
    | loopback and link-local. Narrow this to your actual subnet if you
    | want traffic between separate private ranges treated as external.
    |
    */

    'local_networks' => [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
    ],

    'multicast_networks' => [
        '224.0.0.0/4',
        '255.255.255.255/32',
    ],

    /*
    |--------------------------------------------------------------------------
    | Noise suppression
    |--------------------------------------------------------------------------
    |
    | Traffic matching these CIDRs never produces an alert. Multicast and
    | broadcast are excluded by default: a home router emits IGMP and SSDP
    | constantly, which would otherwise trip the flood rule every window.
    |
    */

    'ignore' => [
        'dst' => ['224.0.0.0/4', '255.255.255.255/32', '239.0.0.0/8'],
        'src' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Retention
    |--------------------------------------------------------------------------
    |
    | Raw events are pruned on this schedule; alerts are kept far longer
    | because they are small and are the actual record of what happened.
    |
    */

    'retention' => [
        // Ordinary noise — benign decoy hits and lone firewall blocks — clears
        // fast. Events that tripped a signature, or came from an IP that raised
        // an alert, are kept far longer as evidence. Alerts outlive both.
        'benign_days' => 7,
        'attacker_days' => 180,
        'alerts_days' => 180,
    ],

    /*
    |--------------------------------------------------------------------------
    | OSINT enrichment
    |--------------------------------------------------------------------------
    |
    | Who gets a passive dossier built, and how often. By default only IPs that
    | did something suspicious — a non-benign decoy signature, an alert, or a
    | firewall block — are enriched, which keeps ordinary visitors unprofiled
    | and stays within free API quotas.
    |
    */

    'enrich' => [
        'benign' => env('BAWLS_ENRICH_BENIGN', false),
        'recheck_days' => 7,     // re-check an IP at most this often
        'per_run' => 50,         // cap IPs enriched per scheduled run
        'lookback_days' => 7,    // only pick candidates seen this recently
    ],

    /*
    |--------------------------------------------------------------------------
    | Alert notifications
    |--------------------------------------------------------------------------
    |
    | When a NEW alert at or above min_severity is raised, POST it to this
    | webhook (ntfy, a Slack/Discord incoming hook, anything that takes JSON).
    | Unset = no notifications; a failing webhook never breaks detection.
    |
    */

    'alert' => [
        'webhook' => env('BAWLS_ALERT_WEBHOOK'),
        'min_severity' => (int) env('BAWLS_ALERT_MIN_SEVERITY', 4),
    ],

    /*
    |--------------------------------------------------------------------------
    | Blocklist + firewall ban feed
    |--------------------------------------------------------------------------
    |
    | never_block: comma-separated IPs/CIDRs that are still recorded and still
    | alert, but never reach the blocklist or the ban feed — so testing an
    | exploit path from home can't lock you out of the server. IPv4 only
    | (Network::inCidr uses ip2long); an IPv6 entry would silently never
    | match, so cover IPv6 in fail2ban's ignoreip instead. Keep the home IP in
    | .env, never in this file: it changes, and this file is in git.
    |
    | When enabled, a new (or newly active) alert from one of `rules` appends
    | a line to `log`, which a fail2ban jail turns into a time-limited ban on
    | every port. web_exploit only by default: it needs a real exploit
    | payload, so it can't be a customer clicking around.
    |
    | export: fail2ban's current bans, as the Lists page shows them. Only
    | root can ask fail2ban, so the installer's bawls-bans timer (root) copies
    | `fail2ban-client get bawls banip --with-time` here every minute.
    |
    */

    'ban' => [
        'enabled' => (bool) env('BAWLS_BAN_ENABLED', false),
        'never_block' => env('BAWLS_NEVER_BLOCK', ''),
        'rules' => env('BAWLS_BAN_RULES', 'web_exploit'),
        'log' => env('BAWLS_BAN_LOG', storage_path('logs/ban.log')),
        'export' => env('BAWLS_BAN_EXPORT', '/var/lib/bawls/bans/banned.txt'),
        // Exploit attempts on your real sites (the site log sensor) ban like
        // decoy ones. Off for a watch period: they're recorded and alerted,
        // and only the decoy bans.
        'site' => (bool) env('BAWLS_SITE_BAN', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Console login path
    |--------------------------------------------------------------------------
    |
    | The sign-in page lives at this secret slug instead of /login, so a
    | scanner sweeping for an admin login never lands on the real one. Set it
    | in the environment to a random string; the app refuses to register its
    | web routes when this is empty or left as "login". The route keeps the
    | name "login", so route('login') and the post-logout redirect still work.
    |
    */

    'login_path' => env('BAWLS_LOGIN_PATH'),

];
