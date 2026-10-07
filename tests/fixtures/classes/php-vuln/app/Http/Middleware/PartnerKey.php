<?php

namespace App\Http\Middleware;

use Closure;

class PartnerKey
{
    public function handle($request, Closure $next)
    {
        if ($request->header('X-Api-Key') !== config('services.partner.key')) {
            abort(401);
        }
        return $next($request);
    }
}
