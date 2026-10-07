<?php

use App\Models\User;
use Illuminate\Support\Facades\Route;

Route::get('/export/users', fn () => User::all());
