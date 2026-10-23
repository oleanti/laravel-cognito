<?php

namespace oleanti\LaravelCognito\Test;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Command;
use Aws\Result;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use oleanti\LaravelCognito\AuthChallenge;
use oleanti\LaravelCognito\CognitoClient;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;
use oleanti\LaravelCognito\Exceptions\SessionExpired;
use oleanti\LaravelCognito\Exceptions\UserCodeInvalid;
use oleanti\LaravelCognito\Test\Support\ArrayStorage;
use oleanti\LaravelCognito\Test\Support\TestConfig;

class CognitoClientTest extends AbstractTestCase
{
    use MockeryPHPUnitIntegration;

    private $aws;

    private CognitoClient $client;

    public function setUp(): void
    {
        parent::setUp();
        TestConfig::$values = [
            'cognito.signupauthflow' => 'USER_PASSWORD_AUTH',
            'cognito.accesstokenstorage' => ArrayStorage::class,
        ];
        ArrayStorage::$result = null;
        $this->aws = Mockery::mock(CognitoIdentityProviderClient::class);
        $this->client = new CognitoClient($this->aws, 'client-id', 'client-secret', 'pool-id');
    }

    private function awsError(string $code, string $message): CognitoIdentityProviderException
    {
        return new CognitoIdentityProviderException($message, new Command('RespondToAuthChallenge'), [
            'code' => $code,
            'message' => $message,
        ]);
    }

    private function secretHash(string $username): string
    {
        return base64_encode(hash_hmac('sha256', $username.'client-id', 'client-secret', true));
    }

    /** @test */
    public function a_challenge_is_returned_as_an_auth_challenge_without_storing_anything()
    {
        $this->aws->shouldReceive('initiateAuth')->once()->andReturn(new Result([
            'ChallengeName' => 'SOFTWARE_TOKEN_MFA',
            'Session' => 'challenge-session',
            'ChallengeParameters' => ['USER_ID_FOR_SRP' => 'sub-123'],
        ]));

        $result = $this->client->authenticate(['email' => 'a@example.com', 'password' => 'secret123']);

        $this->assertInstanceOf(AuthChallenge::class, $result);
        $this->assertSame('SOFTWARE_TOKEN_MFA', $result->name);
        $this->assertSame('challenge-session', $result->session);
        $this->assertSame('sub-123', $result->username);
        $this->assertNull(ArrayStorage::$result);
    }

    /** @test */
    public function tokens_are_stored_when_no_challenge_is_returned()
    {
        $this->aws->shouldReceive('initiateAuth')->once()->andReturn(new Result([
            'AuthenticationResult' => ['AccessToken' => 'at', 'ExpiresIn' => 3600, 'RefreshToken' => 'rt'],
        ]));

        $this->assertTrue($this->client->authenticate(['email' => 'a@example.com', 'password' => 'secret123']));
        $this->assertSame('at', ArrayStorage::$result['AccessToken']);
    }

    /** @test */
    public function a_correct_code_answers_the_challenge_with_the_cognito_username()
    {
        $this->aws->shouldReceive('RespondToAuthChallenge')->once()->with(Mockery::on(function ($payload) {
            return $payload['ChallengeName'] === 'SOFTWARE_TOKEN_MFA'
                && $payload['Session'] === 'challenge-session'
                && $payload['ChallengeResponses']['SOFTWARE_TOKEN_MFA_CODE'] === '123456'
                && $payload['ChallengeResponses']['USERNAME'] === 'sub-123'
                && $payload['ChallengeResponses']['SECRET_HASH'] === $this->secretHash('sub-123');
        }))->andReturn(new Result([
            'AuthenticationResult' => ['AccessToken' => 'at', 'ExpiresIn' => 3600],
        ]));

        $this->assertTrue($this->client->respondToTokenChallange('SOFTWARE_TOKEN_MFA', '123456', 'sub-123', 'challenge-session'));
        $this->assertSame('at', ArrayStorage::$result['AccessToken']);
    }

    /** @test */
    public function the_api_can_answer_a_challenge_without_storing_tokens()
    {
        $this->aws->shouldReceive('RespondToAuthChallenge')->once()->andReturn(new Result([
            'AuthenticationResult' => ['AccessToken' => 'at', 'ExpiresIn' => 3600],
        ]));

        $this->assertTrue($this->client->respondToTokenChallange('SOFTWARE_TOKEN_MFA', '123456', 'sub-123', 's', false));
        $this->assertNull(ArrayStorage::$result);
    }

    /** @test */
    public function select_mfa_type_returns_the_next_challenge()
    {
        $this->aws->shouldReceive('RespondToAuthChallenge')->once()->with(Mockery::on(
            fn ($payload) => $payload['ChallengeResponses']['ANSWER'] === 'SOFTWARE_TOKEN_MFA'
        ))->andReturn(new Result([
            'ChallengeName' => 'SOFTWARE_TOKEN_MFA',
            'Session' => 'next-session',
            'ChallengeParameters' => [],
        ]));

        $next = $this->client->respondToTokenChallange('SELECT_MFA_TYPE', 'SOFTWARE_TOKEN_MFA', 'sub-123', 's');

        $this->assertInstanceOf(AuthChallenge::class, $next);
        $this->assertSame('next-session', $next->session);
        $this->assertSame('sub-123', $next->username);
    }

    /** @test */
    public function a_wrong_code_throws_user_code_invalid()
    {
        $this->aws->shouldReceive('RespondToAuthChallenge')->once()
            ->andThrow($this->awsError('CodeMismatchException', 'Invalid code received for user'));

        $this->expectException(UserCodeInvalid::class);
        $this->client->respondToTokenChallange('SOFTWARE_TOKEN_MFA', '000000', 'sub-123', 's');
    }

    /** @test */
    public function an_expired_challenge_session_throws_session_expired()
    {
        $this->aws->shouldReceive('RespondToAuthChallenge')->once()
            ->andThrow($this->awsError('NotAuthorizedException', 'Invalid session for the user, session is expired.'));

        $this->expectException(SessionExpired::class);
        $this->client->respondToTokenChallange('SOFTWARE_TOKEN_MFA', '123456', 'sub-123', 's');
    }

    /** @test */
    public function an_unknown_challenge_type_is_rejected()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client->respondToTokenChallange('NEW_PASSWORD_REQUIRED', 'x', 'sub-123', 's');
    }

    /** @test */
    public function an_expired_access_token_is_refreshed_with_the_sub_secret_hash()
    {
        $claims = rtrim(strtr(base64_encode(json_encode(['username' => 'sub-123'])), '+/', '-_'), '=');
        ArrayStorage::$result = [
            'AccessToken' => "header.{$claims}.signature",
            'ExpiresAt' => time() - 10,
            'RefreshToken' => 'rt',
        ];
        $this->aws->shouldReceive('initiateAuth')->once()->with(Mockery::on(function ($payload) {
            return $payload['AuthFlow'] === 'REFRESH_TOKEN_AUTH'
                && $payload['AuthParameters']['REFRESH_TOKEN'] === 'rt'
                && $payload['AuthParameters']['SECRET_HASH'] === $this->secretHash('sub-123');
        }))->andReturn(new Result([
            'AuthenticationResult' => ['AccessToken' => 'fresh', 'ExpiresIn' => 3600],
        ]));
        // ArrayStorage does not add ExpiresAt; the refreshed token only has to be returned.
        $this->assertSame('fresh', $this->client->getAccessToken());
    }

    /** @test */
    public function a_session_without_cognito_tokens_has_no_access_token()
    {
        $this->expectException(NoAccessTokenAvailable::class);
        $this->client->getAccessToken();
    }

    /** @test */
    public function mfa_state_is_read_with_the_admin_api()
    {
        $this->aws->shouldReceive('AdminGetUser')->once()->andReturn(new Result([
            'UserMFASettingList' => ['SOFTWARE_TOKEN_MFA'],
            'PreferredMfaSetting' => 'SOFTWARE_TOKEN_MFA',
        ]));

        $this->assertSame(
            ['enabled' => ['SOFTWARE_TOKEN_MFA'], 'preferred' => 'SOFTWARE_TOKEN_MFA'],
            $this->client->getMfaState('a@example.com')
        );
    }

    /** @test */
    public function disable_mfa_leaves_out_email_settings_on_lite_pools()
    {
        $this->aws->shouldReceive('adminSetUserMFAPreference')->once()->with(Mockery::on(
            fn ($payload) => ! isset($payload['EmailMfaSettings'])
                && $payload['SoftwareTokenMfaSettings']['Enabled'] === false
                && $payload['Username'] === 'a@example.com'
        ));

        $this->client->disableMfa('a@example.com');
    }
}
