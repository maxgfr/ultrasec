<?php

namespace App\Support;

class RememberCookie
{
    public static function issue(string $token): void
    {
        setcookie('sid', $token);
    }
}
