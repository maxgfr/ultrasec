<?php

use App\Models\User;
use Illuminate\Support\Facades\Route;

Route::get('/export/users', fn () => User::query()->orderBy('id')->paginate(500));
