<?php

namespace App\Http\Controllers;

use App\Models\Alert;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

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

    public function acknowledgeAll(Request $request): RedirectResponse
    {
        return $this->closeOpen($request, 'acked');
    }

    public function resolveAll(Request $request): RedirectResponse
    {
        return $this->closeOpen($request, 'resolved');
    }

    /** From the lists page: an address's hidden and dismissed alerts go back to the open panel. */
    public function reopen(Request $request): RedirectResponse
    {
        Alert::reopenFor($request->validate(['ip' => ['required', 'ip']])['ip']);

        return back();
    }

    /**
     * Every open alert up to the newest one the page had seen ("through"),
     * so one that opened after the button was drawn is never closed unread.
     */
    private function closeOpen(Request $request, string $status): RedirectResponse
    {
        $through = $request->validate(['through' => ['required', 'integer', 'min:1']])['through'];

        Alert::open()->where('id', '<=', $through)->update(['status' => $status]);

        return back();
    }
}
