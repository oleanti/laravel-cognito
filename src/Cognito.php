<?php

namespace oleanti\LaravelCognito;

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
     * Get the name of the user model used by the application.
     *
     * @return string
     */
    public static function userModel()
    {
        return config('cognito.usermodel', 'App\Models\User');
    }
}
