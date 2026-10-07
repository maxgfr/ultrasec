<?php

namespace App\Http\Middleware;

use Closure;

class PartnerKey
{
    public function handle($request, Closure $next)
    {
        if (! hash_equals((string) config('services.partner.key'), (string) $request->header('X-Api-Key'))) {
            abort(401);
        }
        return $next($request);
    }
}
