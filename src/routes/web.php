<?php

use Illuminate\Support\Facades\Route;
use oleanti\LaravelCognito\Http\Controllers\VerificationController;

Route::middleware([
    'web',
])->group(function () {
    Route::get('/verification', [VerificationController::class, 'view'])->name('cognito.verification');
    Route::post('/verification', [VerificationController::class, 'post'])->name('cognito.verificationpost');
});
