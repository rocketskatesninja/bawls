<?php

namespace App\Http\Controllers;

use App\Services\Blocklist;
use Illuminate\Http\Response;

/** The blocklist as plain text, one address per line, for other firewalls. */
class BlocklistController extends Controller
{
    public function show(): Response
    {
        return response(Blocklist::text(), 200, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Content-Disposition' => 'attachment; filename="bawls-blocklist.txt"',
        ]);
    }
}
