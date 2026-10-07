<?php

namespace App\Support;

class Flags
{
    public static function debug(): bool
    {
        return (bool) getenv('APP_DEBUG');
    }
}
