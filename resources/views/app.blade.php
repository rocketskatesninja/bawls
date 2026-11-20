<!DOCTYPE html>
@php($settings = app(\App\Services\Settings::class))
{{-- The accent is a setting: painted here so the first frame is already the right colour. --}}
<html lang="en" class="dark" style="--color-phosphor: {{ $settings->accent() }}; --color-phosphor-dim: {{ $settings->accentDim() }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23070b09'/%3E%3Ccircle cx='16' cy='16' r='9' fill='none' stroke='{{ rawurlencode($settings->accent()) }}' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='{{ rawurlencode($settings->accent()) }}'/%3E%3C/svg%3E">
    <title inertia>{{ config('app.name', 'Bawls') }}</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    @inertiaHead
</head>
<body class="crt antialiased">
    @inertia
</body>
</html>
