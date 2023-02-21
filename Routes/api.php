<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Modules\AuthWithJWT\Http\Controllers\ApiController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
    Route::post('login',[ApiController::class,'authenticate'])->name('auth.login');
    Route::post('register',[ApiController::class,'register'])->name('auth.register');
    Route::get('forgot-password',[ApiController::class,'forgotPassword'])->name('auth.forget_password');

    Route::group(['middleware' => ['jwt.verify']], function() {
        Route::get('logout', [ApiController::class, 'logout'])->name('auth.logout');
        Route::get('get_user',[ApiController::class,'getUser'])->name('auth.get_user');
        Route::put('update_user',[ApiController::class,'updateUser'])->name('auth.update_user');
        Route::post('change-password',[ApiController::class,'changePassword'])->name('auth.change_password');
        Route::post('user-logs',[ApiController::class,'userLogs'])->name('auth.user_logs');
    });

// Route::middleware('auth:api')->get('/authwithjwt', function (Request $request) {
//     return $request->user();
// });
