<?php

namespace App\Http\Middleware;

use Closure;

class SecurityHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->set('Content-Security-Policy', "default-src 'self'");
        $response->headers->set('X-Frame-Options', 'DENY');
        return $response;
    }
}
