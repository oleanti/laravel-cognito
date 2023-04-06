<?php

namespace oleanti\LaravelCognito\AccessToken;

interface AuthenticationResultStorageInterface
{
    public function get(): AuthResult;
    public function set(array $result);
}
