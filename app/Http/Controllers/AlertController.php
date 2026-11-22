<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use Illuminate\Http\RedirectResponse;

class AlertController extends Controller
{
    public function acknowledge(Alert $alert): RedirectResponse
    {
        $alert->update(['status' => 'acked']);

        return back();
    }

    public function resolve(Alert $alert): RedirectResponse
    {
        $alert->update(['status' => 'resolved']);

        return back();
    }
}
