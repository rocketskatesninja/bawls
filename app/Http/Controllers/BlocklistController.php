<?php

namespace App\Http\Controllers;

use App\Services\Blocklist;
use Illuminate\Http\Response;

class BlocklistController extends Controller
{
    public function show(): Response
    {
        return response(Blocklist::text(), 200, ['Content-Type' => 'text/plain; charset=utf-8']);
    }
}
