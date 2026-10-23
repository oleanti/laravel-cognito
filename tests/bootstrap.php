<?php

use oleanti\LaravelCognito\Test\Support\TestConfig;

// The package has no Laravel in require-dev: stub the two helpers CognitoClient calls.

require __DIR__.'/../vendor/autoload.php';

if (! function_exists('config')) {
    function config($key = null, $default = null)
    {
        return TestConfig::get($key, $default);
    }
}

if (! function_exists('request')) {
    function request()
    {
        return new class
        {
            public function ip()
            {
                return '127.0.0.1';
            }
        };
    }
}
