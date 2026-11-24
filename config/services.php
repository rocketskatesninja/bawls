<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Resend, Postmark, AWS, and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | OSINT enrichment sources
    |--------------------------------------------------------------------------
    |
    | Passive lookups used to build a dossier on an attacker IP. MaxMind reads
    | from a local database (no network call); the others are public APIs.
    | GreyNoise, Shodan InternetDB and RDAP work without a key; AbuseIPDB and
    | an optional GreyNoise key only add data when present. Nothing here ever
    | connects back to or scans the IP being looked up.
    |
    */

    'maxmind' => [
        'license_key' => env('MAXMIND_LICENSE_KEY'),
        'db_path' => storage_path('geoip'),
    ],

    'abuseipdb' => [
        'key' => env('ABUSEIPDB_KEY'),
    ],

    'greynoise' => [
        'key' => env('GREYNOISE_KEY'),
    ],

];
