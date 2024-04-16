<?php

return [
    'credentials' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'token' => null,
    ],

    'app_client_id' => env('AWS_COGNITO_CLIENT_ID'),
    'app_client_secret' => env('AWS_COGNITO_CLIENT_SECRET'),
    'user_pool_id' => env('AWS_COGNITO_USER_POOL_ID'),
    'region' => env('AWS_COGNITO_REGION', 'us-east-1'),
    'version' => env('AWS_COGNITO_VERSION', 'latest'),
    'add_missing_local_user_sso' => true,
    'signupauthflow' => 'USER_PASSWORD_AUTH', // USER_SRP_AUTH|USER_PASSWORD_AUTH
    'autoconfirmusersignup' => true,
    'delete_cognito_user_on_model_delete' => true,
    'force_new_user_email_verified' => false,
    'usermodel' => 'App\Models\User',
    'username' => 'email',
    'usermodel_mapping' => [
        'phone' => 'phone_number',
        'name' => 'name',
        'email' => 'email',
    ],
    'cognito_field_caster' => [
        'phone_number' => App\Casts\UserPhone::class,
    ],
    'accesstokenstorage' => oleanti\LaravelCognito\AccessToken\SessionStorage::class,
    'routes' => [
        'mfa_challenge' => 'login.mfa',
    ],
];
