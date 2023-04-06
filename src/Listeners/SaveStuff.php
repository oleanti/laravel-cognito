<?php

namespace oleanti\LaravelCognito\Listeners;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Support\Facades\App;
use oleanti\LaravelCognito\CognitoClient;

class SaveStuff
{
    public function handle(Authenticated $event)
    {

        if($event->guard === 'cognito') {
            $client = App::make(CognitoClient::class);
            //session(['hri', $client->getAuthenticationResult()]);

        }

    }
}
