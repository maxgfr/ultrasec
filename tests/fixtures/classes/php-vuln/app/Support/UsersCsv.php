<?php

namespace App\Support;

/** Streams the users as a CSV download. */
class UsersCsv
{
    public static function write($out, iterable $users): void
    {
        foreach ($users as $user) {
            fputcsv($out, [$user->name, $user->email]);
        }
    }
}
