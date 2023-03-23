<?php

namespace oleanti\LaravelCognito\Test;

use Carbon\Carbon;
use Faker\Factory as Faker;
use PHPUnit\Framework\TestCase;

abstract class AbstractTestCase extends TestCase
{
    /**
     * @var int
     */
    protected $testNowTimestamp;

    public $faker;

    public function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
        $this->faker = Faker::create();
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
        \Mockery::close();

        parent::tearDown();
    }
}
