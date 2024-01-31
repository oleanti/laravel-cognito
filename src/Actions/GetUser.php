<?php

namespace oleanti\LaravelCognito\Actions;

use oleanti\LaravelCognito\Cognito;
use oleanti\LaravelCognito\CognitoClient;
use Illuminate\Support\Carbon;

class GetUser
{
    public static function retrieveByCredentials(array $credentials, $provider){
        $user = $provider->retrieveByCredentials($credentials);
        if(is_null($user)){
            $username = $credentials[config('cognito.username')];
            $user = CreateUser::createFromCognito($username);
        }     
        return $user;   
    }
}
