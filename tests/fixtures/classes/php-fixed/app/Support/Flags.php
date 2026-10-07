<?php

namespace App\Support;

class Flags
{
    public static function debug(): bool
    {
        return filter_var(getenv('APP_DEBUG'), FILTER_VALIDATE_BOOLEAN);
    }
}
