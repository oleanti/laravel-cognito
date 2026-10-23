<?php

namespace oleanti\LaravelCognito\Test\Support;

use oleanti\LaravelCognito\AccessToken\AuthenticationResultStorageInterface;
use oleanti\LaravelCognito\AccessToken\AuthResult;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;

class ArrayStorage implements AuthenticationResultStorageInterface
{
    public static ?array $result = null;

    public function get(): AuthResult
    {
        if (static::$result === null) {
            throw new NoAccessTokenAvailable;
        }

        return new AuthResult(static::$result);
    }

    public function set(array $result)
    {
        static::$result = array_merge(static::$result ?? [], $result);
    }
}
