<?php

namespace App\Support;

class ClientIp
{
    public static function current(): string
    {
        return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '')[0]);
    }
}
