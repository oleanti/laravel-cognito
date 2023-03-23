<?php

namespace OleAnti\LaravelCognito\Test;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    /**
     * @var int
     */
    protected $testNowTimestamp;

    public function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
        \Mockery::close();

        parent::tearDown();
    }
}
