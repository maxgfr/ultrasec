<?php

namespace App\Support;

/** Streams the users as a CSV download. */
class UsersCsv
{
    private static function cell($value): string
    {
        $s = (string) $value;
        return preg_match('/^[=+\-@\t\r]/', $s) ? "'".$s : $s;
    }

    public static function write($out, iterable $users): void
    {
        foreach ($users as $user) {
            fputcsv($out, [self::cell($user->name), self::cell($user->email)]);
        }
    }
}
