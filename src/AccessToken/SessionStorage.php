<?php

namespace oleanti\LaravelCognito\AccessToken;

use Illuminate\Support\Facades\App;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;

class SessionStorage implements AuthenticationResultStorageInterface
{
    protected static $cache = null;

    public function __construct($initalData = null)
    {
        if (is_array($initalData)) {
            static::$cache = new AuthResult($initalData);
        }
    }

    public function get(): AuthResult
    {
        $accessResult = App::make('session')->get('cognito.AuthenticationResult');
        if (! is_array($accessResult)) {
            throw new NoAccessTokenAvailable;
        }
        static::$cache = new AuthResult($accessResult);

        return static::$cache;
    }

    public function set(array $result)
    {

        $current = [];
        $previousAuthResult = static::$cache;

        if (is_null($previousAuthResult)) {
            try {
                $previousAuthResult = $this->get();
                $current = $previousAuthResult->getAccessResultArray();
            } catch (NoAccessTokenAvailable $e) {
                $current = [];
            }
        } else {
            $current = $previousAuthResult->getAccessResultArray();
        }

        App::make('session')->put('cognito.AuthenticationResult', array_merge($current, $result));
    }

    public function getCached()
    {
        return static::$cache;
    }
}
