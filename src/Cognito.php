<?php

namespace OleAnti\LaravelCognito;

use OleAnti\LaravelCognito\Http\Responses\SimpleViewResponse;
use OleAnti\LaravelCognito\Http\Responses\VerifyViewResponse;
use OleAnti\LaravelCognito\Contracts\VerifyViewResponse as VerifyViewResponseContract;


class Cognito
{
    /**
     * Get the username used for authentication.
     *
     * @return string
     */
    public static function username()
    {
        return config('cognito.username', 'email');
    }

    /**
     * The user model
     *
     * @var string
     */
    public static $userModel = 'App\\Models\\User';

    /**
     * Get the name of the user model used by the application.
     *
     * @return string
     */
    public static function userModel()
    {
        return static::$userModel;
    }
}
