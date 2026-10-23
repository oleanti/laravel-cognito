<?php

namespace oleanti\LaravelCognito\AccessToken;

use Aws\Token\Token;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;
use oleanti\LaravelCognito\Exceptions\NoRefreshTokenAvailable;

class AuthResult
{
    private $accessResult;

    // $accessResult['AccessToken']
    // $accessResult['ExpiresIn']
    // $accessResult['TokenType']
    // $accessResult['RefreshToken']
    // $accessResult['IdToken']
    // $accessResult['ExpiresAt']  absolute unix time, added by the storage
    public function __construct(array $result)
    {
        $this->accessResult = $result;

    }

    public function getAwsToken(): Token
    {
        if (is_null($this->accessResult) || ! isset($this->accessResult['AccessToken'])) {
            throw new NoAccessTokenAvailable;
        }

        // Results stored before ExpiresAt existed count as expired, so they get refreshed.
        return new Token($this->accessResult['AccessToken'], $this->accessResult['ExpiresAt'] ?? 0);
    }

    public function getRefreshToken(): Token
    {
        if (is_null($this->accessResult) || ! isset($this->accessResult['RefreshToken'])) {
            throw new NoRefreshTokenAvailable;
        }

        return new Token($this->accessResult['RefreshToken']);
    }

    public function getAccessResultArray()
    {
        return $this->accessResult;
    }
}
