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
    public function __construct(array $result)
    {
        $this->accessResult = $result;

    }

    public function getAwsToken(): Token
    {
        if (is_null($this->accessResult) || ! isset($this->accessResult['AccessToken'])) {
            throw new NoAccessTokenAvailable;
        }

        return new Token($this->accessResult['AccessToken'], $this->accessResult['ExpiresIn']);
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
