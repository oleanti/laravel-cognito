<?php

namespace oleanti\LaravelCognito\Test;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use oleanti\LaravelCognito\AccessToken\SessionStorage;

class SessionStorageTest extends AbstractTestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Test to store and to get a accessresult array
     */
    /** @test */
    public function session_storage_test()
    {
        $accessResult = [];
        $accessResult['AccessToken'] = $this->faker->regexify('[A-Z][0-4]{4096}');
        $accessResult['ExpiresIn'] = 3600;
        $accessResult['TokenType'] = 'bearer';
        $accessResult['RefreshToken'] = $this->faker->regexify('[A-Z][0-4]{4096}');
        $accessResult['IdToken'] = $this->faker->regexify('[A-Z][0-4]{4096}');

        $mockSession = Mockery::mock('session');

        $mockSession->shouldReceive('get')
        ->with('cognito.AuthenticationResult')
        ->andReturn([])
        ->once();

        $mockSession->shouldReceive('get')
        ->with('cognito.AuthenticationResult')
        ->andReturn($accessResult)
        ->once();

        $mockSession->shouldReceive('put')
        ->with('cognito.AuthenticationResult', $accessResult)
        ->once();

        $mockedApp = Mockery::mock('alias:'.\Illuminate\Support\Facades\App::class);
        $mockedApp->shouldReceive('make')->with('session')->andReturn($mockSession);

        $storage = new SessionStorage;
        $storage->set($accessResult);
        $authResult = $storage->get();

        $awsToken = $authResult->getAwsToken();
        $awsRefreshToken = $authResult->getRefreshToken();
        $this->assertEquals($accessResult['AccessToken'], $awsToken->getToken());
        $this->assertEquals($accessResult['ExpiresIn'], $awsToken->getExpiration());
        $this->assertEquals($accessResult['RefreshToken'], $awsRefreshToken->getToken());
    }

    /**
     * Update a result with only a new AccessToken
     */
    /** @test */
    public function session_partial_update_test()
    {
        $accessResult = [];
        $accessResult['AccessToken'] = 'old';
        $accessResult['ExpiresIn'] = 3600;
        $accessResult['TokenType'] = 'bearer';
        $accessResult['RefreshToken'] = 'old';
        $accessResult['IdToken'] = 'old';

        $newAccessResult = [];
        $newAccessResult['AccessToken'] = 'new';

        $shouldStore = $accessResult;
        $shouldStore['AccessToken'] = $newAccessResult['AccessToken'];

        $storage = new SessionStorage($accessResult);

        $mockSession = Mockery::mock('session');
        $mockSession->shouldReceive('get')
        ->with('cognito.AuthenticationResult')
        ->andReturn($shouldStore)
        ->once();
        $mockSession->shouldReceive('put')
        ->with('cognito.AuthenticationResult', $shouldStore)
        ->once();
        $mockedApp = Mockery::mock('alias:'.\Illuminate\Support\Facades\App::class);
        $mockedApp->shouldReceive('make')->with('session')->andReturn($mockSession);

        $storage->set($newAccessResult);
        $authResult = $storage->get();
        $awsToken = $authResult->getAwsToken();
        $awsRefreshToken = $authResult->getRefreshToken();
        $this->assertEquals($newAccessResult['AccessToken'], $awsToken->getToken());
        $this->assertEquals($accessResult['ExpiresIn'], $awsToken->getExpiration());
        $this->assertEquals($accessResult['RefreshToken'], $awsRefreshToken->getToken());
    }
}
