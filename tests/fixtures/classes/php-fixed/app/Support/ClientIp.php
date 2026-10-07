<?php

namespace App\Support;

class ClientIp
{
    // One trusted proxy: the client is the last hop, the one it appended.
    public static function current(): string
    {
        $hops = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        return trim(end($hops));
    }
}
