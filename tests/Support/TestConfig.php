<?php

namespace oleanti\LaravelCognito\Test\Support;

class TestConfig
{
    public static array $values = [];

    public static function get($key, $default = null)
    {
        return array_key_exists($key, static::$values) ? static::$values[$key] : $default;
    }
}
