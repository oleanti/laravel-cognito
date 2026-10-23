<?php

namespace oleanti\LaravelCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Validation\ValidationException;
use oleanti\LaravelCognito\Exceptions\AccessDeniedException;
use oleanti\LaravelCognito\Exceptions\AccessTokenExpired;
use oleanti\LaravelCognito\Exceptions\InvalidConfiguration;
use oleanti\LaravelCognito\Exceptions\InvalidParameterException;
use oleanti\LaravelCognito\Exceptions\InvalidPassword;
use oleanti\LaravelCognito\Exceptions\LimitExceededException;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;
use oleanti\LaravelCognito\Exceptions\NotAuthorizedException;
use oleanti\LaravelCognito\Exceptions\SessionExpired;
use oleanti\LaravelCognito\Exceptions\UserCodeInvalid;
use oleanti\LaravelCognito\Exceptions\UserNotConfirmedException;
use oleanti\LaravelCognito\Exceptions\UserNotFoundException;
use oleanti\LaravelCognito\Exceptions\OtpAlreadyUsed;
use Illuminate\Support\Facades\Log;

class CognitoClient
{
    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * @var string
     */
    protected $poolId;

    /**
     * @var array
     */
    protected $authenticationResult;

    /**
     * @var array
     */
    protected $codeDeliveryDetails;

    /**
     * CognitoClient constructor.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  string  $poolId
     */
    public function __construct(
        CognitoIdentityProviderClient $client,
        $clientId,
        $clientSecret,
        $poolId
    ) {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    private function getSecretHash($username)
    {
        return base64_encode(hash_hmac('sha256', $username.$this->clientId, $this->clientSecret, true));
    }

    public function mapUserAttributesToCognito($attributes): array
    {
        $fields = [];
        $mappedField = config('cognito.usermodel_mapping');

        foreach ($mappedField as $localField => $cognitoField) {
            if (array_key_exists($localField, $attributes)) {
                $cognitoValue = $attributes[$localField];
                $fields[] = [
                    'Name' => $cognitoField,
                    'Value' => $cognitoValue,
                ];
            }
        }

        return $fields;
    }

    public function getUser($username)
    {
        try {
            $user = $this->client->AdminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (\InvalidArgumentException $e) {
            if (str_contains($e->getMessage(), '[UserPoolId] is missing and is a required parameter')) {
                throw new InvalidConfiguration('UserPoolId is missing and is a required parameter');
            }
            throw $e;
        }

        return $user;
    }

    public function initiateauth(string $username, string $password)
    {
        switch (config('cognito.signupauthflow')) {
            case 'USER_SRP_AUTH':
                // https://gist.github.com/jenky/a4465f73adf90206b3e98c3d36a3be4f
                return;
            default:
                return $this->USER_PASSWORD_AUTH($username, $password);
        }
    }

    private function USER_PASSWORD_AUTH($username, $password)
    {
        $parameters = [
            'AuthFlow' => 'USER_PASSWORD_AUTH', // USER_SRP_AUTH|REFRESH_TOKEN_AUTH|REFRESH_TOKEN|CUSTOM_AUTH|ADMIN_NO_SRP_AUTH|USER_PASSWORD_AUTH|ADMIN_USER_PASSWORD_AUTH
            'AuthParameters' => [
                'USERNAME' => $username,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->getSecretHash($username),
            ],
            'ClientId' => $this->clientId,
            'UserContextData' => [
                'IpAddress' => request()->ip(),
            ],
        ];
        try {
            $result = $this->client->initiateAuth($parameters);

            return $result;
        } catch (CognitoIdentityProviderException $e) {
            Log::info($e->getAwsErrorMessage());
            // https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CognitoIdentityProvider.Exception.CognitoIdentityProviderException.html
            switch ($e->getAwsErrorCode()) {
                case 'InvalidParameterException':
                    throw new InvalidParameterException($e->getAwsErrorMessage());
                    break;
                case 'UserNotConfirmedException':
                    throw new UserNotConfirmedException($e->getAwsErrorMessage());
                    break;
                default:
                    throw $e;
            }
        }
    }

    /**
     * @return true|AuthChallenge|false true when tokens were stored, an AuthChallenge when Cognito
     *                                  wants a second step (MFA, new password) before issuing tokens
     */
    public function authenticate($credentials)
    {
        $username = $credentials['email'];
        $password = $credentials['password'];
        try {
            $result = $this->initiateauth($username, $password);
        } catch (CognitoIdentityProviderException $e) {
            Log::info($e->getAwsErrorMessage());
            // https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CognitoIdentityProvider.Exception.CognitoIdentityProviderException.html
            if($e->getAwsErrorMessage() == 'Password attempts exceeded'){
                throw new LimitExceededException($e->getAwsErrorMessage());
            }
            if($e->getAwsErrorMessage() == 'Incorrect username or password.'){
                throw new InvalidPassword($e->getAwsErrorMessage());
            }            
            switch ($e->getAwsErrorCode()) {
                
                case 'NotAuthorizedException':
                    throw new NotAuthorizedException($username);
                    break;
                case 'NEW_PASSWORD_REQUIRED':
                    throw $e;
                    break;
                default:
                    throw $e;
            }
        }

        if (isset($result['AuthenticationResult'])) {
            $this->authenticationResult = $result['AuthenticationResult'];
            $this->storeAccessToken();

            return true;
        }
        if (isset($result['ChallengeName'])) {
            return AuthChallenge::fromResult($result, $username);
        }

        return false;
    }

    public function changePassword(string $accessToken, string $previousPassword, string $newPassword)
    {
        $parameters = [
            'AccessToken' => $accessToken,
            'PreviousPassword' => $previousPassword,
            'ProposedPassword' => $newPassword,
        ];
        try {
            $result = $this->client->changePassword($parameters);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() == 'NotAuthorizedException') {
                if ($e->getAwsErrorMessage() == 'Access Token has expired') {
                    throw new AccessTokenExpired;
                }
                throw ValidationException::withMessages([
                    'current_password' => __('validation.current_password'),
                ]);
            } elseif ($e->getAwsErrorCode() == 'LimitExceededException') {
                throw new LimitExceededException($e->getAwsErrorMessage());
            } else {
                throw $e;
            }
        }

        return $result;
    }

    public function adminSetUserPassword($username, $password, $permanent = true)
    {
        $parameters = [
            'Password' => $password,
            'Permanent' => $permanent,
            'Username' => $username,
            'UserPoolId' => $this->poolId,
        ];
        try {
            return $this->client->adminSetUserPassword($parameters);
        } catch (CognitoIdentityProviderException $e) {
            if ($e->getAwsErrorCode() === 'UserNotFoundException') {
                throw new UserNotFoundException($username);
            }

            if ($e->getAwsErrorCode() === 'InvalidPasswordException') {
                throw new InvalidPassword($e->getAwsErrorMessage());
            }
            throw $e;
        }
    }

    public function adminCreateUser($username, $attributes = [])
    {
        $userAttributes = $this->mapUserAttributesToCognito($attributes);
        $parameters = [
            'UserPoolId' => $this->poolId,
            'MessageAction' => 'SUPPRESS',
            'Username' => $username,
            'UserAttributes' => $userAttributes,
        ];
        $result = $this->client->AdminCreateUser($parameters);

        return $result;
    }

    public function signUp($username, $password, $attributes)
    {
        $userAttributes = $this->mapUserAttributesToCognito($attributes);
        $parameters = [
            'ClientId' => $this->clientId,
            'Password' => $password,
            'SecretHash' => $this->getSecretHash($username),
            'UserContextData' => [
                'IpAddress' => request()->ip(),
            ],
            'Username' => $username,

        ];
        if (count($userAttributes) > 0) {
            $parameters['UserAttributes'] = $userAttributes;
        }
        try {
            $result = $this->client->signUp($parameters);
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                
                case 'InvalidPasswordException':
                    throw ValidationException::withMessages([
                        'password' => [$e->getAwsErrorMessage()],
                    ]);
                    break;
                case 'UsernameExistsException':
                    throw ValidationException::withMessages([
                        Cognito::username() => trans('validation.unique', [
                            'attribute' => Cognito::username(),
                        ]),
                    ]);
                    break;
                case 'InvalidParameterException':
                    throw ValidationException::withMessages([
                        'password' => $e->getAwsErrorMessage(),
                    ]);
                default:
                    throw $e;
            }

        }
        $cognito_verified_at = null;
        if ((isset($result['data']['UserConfirmed']) && $result['data']['UserConfirmed']) || config('cognito.autoconfirmusersignup') === true) {
            $cognito_verified_at = now();
        } elseif ($result['UserConfirmed'] === false && isset($result['CodeDeliveryDetails'])) {
            // Only pools with auto-verified attributes send a confirmation code.
            $this->codeDeliveryDetails = $result['CodeDeliveryDetails'];
            $this->storeCodeDeliveryDetails();
        }
        $store = [            
            'email' => $username,
            'cognito_uuid' => $result['UserSub'],
            'cognito_username' => $username,
            'cognito_verified_at' => $cognito_verified_at,
        ];
        if(isset($attributes['name'])){
           $store['name'] = $attributes['name']; 
        }
        $user = Cognito::userModel()::create($store);
        if (config('cognito.autoconfirmusersignup') === true) {
            try {
                $this->adminConfirmSignUp($username);
            } catch (AccessDeniedException $e) {
                throw new NotAuthorizedException($e->getMessage());
            }
        }

        if (config('cognito.force_new_user_email_verified') === true) {
            $this->adminUpdateUserAttributes($username, [[
                'Name' => 'email_verified',
                'Value' => 'true',
            ]]);
            $user->markEmailAsVerified();
        }

        return $user;
    }
    public function adminConfirmSignUp($username)
    {
        try {
            return $this->client->adminConfirmSignUp([
                'UserPoolId' => $this->poolId,
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            // Confirming an already confirmed user is a no-op, not an error.
            if (str_contains((string) $e->getAwsErrorMessage(), 'Current status is CONFIRMED')) {
                return null;
            }
            switch ($e->getAwsErrorCode()) {
                case 'UserNotFoundException':
                    throw new UserNotFoundException($username);
                    break;
                case 'AccessDeniedException':
                    throw new AccessDeniedException($e->getAwsErrorMessage());
                default:
                    throw $e;
            }

        }
    }
    public function adminUpdateUserAttributes($username, $attributes)
    {
        try {
            $this->client->adminUpdateUserAttributes([
                'UserAttributes' => $attributes,
                'UserPoolId' => $this->poolId,
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                case 'UserNotFoundException':
                    throw new UserNotFoundException($username);
                    break;
                case 'AccessDeniedException':
                    throw new AccessDeniedException($e->getAwsErrorMessage());
                default:
                    throw $e;
            }

        }
    }

    public function adminDeleteUser($username)
    {
        try {
            $this->client->adminDeleteUser([
                'UserPoolId' => $this->poolId,
                'Username' => $username, // REQUIRED
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw $e;
        }
    }

    public function confirmSignUp($username, $code)
    {
        try {
            $this->client->confirmSignUp([
                'ClientId' => $this->clientId,
                'ConfirmationCode' => $code,
                'SecretHash' => $this->getSecretHash($username),
                'UserContextData' => [
                    'IpAddress' => request()->ip(),
                ],
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                case 'CodeMismatchException':
                    throw ValidationException::withMessages([
                        'code' => $e->getAwsErrorMessage(),
                    ]);
                    break;
                case 'AccessDeniedException':
                    throw new AccessDeniedException($e->getAwsErrorMessage());
                default:
                    throw $e;
            }
        }
    }

    public function resendConfirmationCode($username)
    {
        try {
            $result = $this->client->resendConfirmationCode([
                'ClientId' => $this->clientId,
                'SecretHash' => $this->getSecretHash($username),
                'UserContextData' => [
                    'EncodedData' => '<string>',
                    'IpAddress' => '<string>',
                ],
                'UserContextData' => [
                    'IpAddress' => request()->ip(),
                ],
                'Username' => $username,
            ]);

            return $result;
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                case 'InvalidParameterException':
                    throw new InvalidParameterException($e->getAwsErrorMessage());
                case 'NotAuthorizedException':
                    throw new NotAuthorizedException($e->getAwsErrorMessage());
                default:
                    throw $e;
            }
        }
    }

    public function refreshAccessToken()
    {
        // REFRESH_TOKEN_AUTH wants the SECRET_HASH of the Cognito username (the sub when e-mail is
        // the sign-in alias), not the e-mail. The stored access token carries it as a claim.
        $username = $this->cognitoUsernameFromAccessToken($this->getStoredAccessToken());

        $parameters = [
            'AuthFlow' => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $this->getRefreshToken(),
                'SECRET_HASH' => $this->getSecretHash($username),
            ],
            'ClientId' => $this->clientId,
            'UserContextData' => [
                'IpAddress' => request()->ip(),
            ],
        ];
        try {
            $result = $this->client->initiateAuth($parameters);
            if (isset($result['AuthenticationResult'])) {
                $this->authenticationResult = $result['AuthenticationResult'];
                $this->storeAccessToken();

                return true;
            }

            return $result;
        } catch (CognitoIdentityProviderException $e) {
            // https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CognitoIdentityProvider.Exception.CognitoIdentityProviderException.html
            switch ($e->getAwsErrorCode()) {
                case 'InvalidParameterException':
                    throw new InvalidParameterException($e->getAwsErrorMessage());
                    break;
                default:
                    throw $e;
            }
        }

    }

    public function getUserAttributeVerificationCode(string $attributeName)
    {
        $payload = [
            'AccessToken' => $this->getAccessToken(),
            'AttributeName' => $attributeName,
        ];
        $response = $this->client->GetUserAttributeVerificationCode($payload);

        return true;
    }

    public function verifyUserAttribute(string $attributeName, $code)
    {
        $payload = [
            'AccessToken' => $this->getAccessToken(),
            'AttributeName' => $attributeName,
            'Code' => $code,
        ];
        $response = $this->client->VerifyUserAttribute($payload);

        return true;
    }

    public function storeAccessToken()
    {
        $class = config('cognito.accesstokenstorage');
        $storage = new $class;
        $storage->set($this->authenticationResult);
    }

    public function storeCodeDeliveryDetails()
    {
        session()->put('cognito.CodeDeliveryDetails', $this->codeDeliveryDetails);
    }

    /**
     * The current user's access token, refreshed with the refresh token when it has expired.
     *
     * @throws NoAccessTokenAvailable when this session never authenticated against Cognito
     */
    public function getAccessToken()
    {
        $class = config('cognito.accesstokenstorage');
        $storage = new $class;
        $token = $storage->get()->getAwsToken();

        if ($token->isExpired()) {
            $this->refreshAccessToken();
            $token = $storage->get()->getAwsToken();
        }

        return $token->getToken();
    }

    private function getStoredAccessToken(): string
    {
        $class = config('cognito.accesstokenstorage');
        $storage = new $class;

        return $storage->get()->getAwsToken()->getToken();
    }

    /**
     * Reads the `username` claim without verifying the signature: it only feeds the SECRET_HASH,
     * and Cognito itself rejects a refresh token that does not belong to that user.
     */
    private function cognitoUsernameFromAccessToken(string $accessToken): string
    {
        $parts = explode('.', $accessToken);
        $claims = isset($parts[1]) ? json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true) : null;
        if (! is_array($claims) || ! isset($claims['username'])) {
            throw new NoAccessTokenAvailable;
        }

        return $claims['username'];
    }

    public function getRefreshToken()
    {
        $class = config('cognito.accesstokenstorage');
        $storage = new $class;
        $authResult = $storage->get();

        $refreshToken = $authResult->getRefreshToken();

        return $refreshToken->getToken();
    }

    public function getCodeDeliveryDetails()
    {
        return session('cognito.CodeDeliveryDetails');
    }

    /**
     * Answers an MFA challenge from authenticate(). For SELECT_MFA_TYPE, $otp is the chosen
     * challenge name (e.g. SOFTWARE_TOKEN_MFA) and the next AuthChallenge is returned.
     *
     * @param  bool  $storeTokens  false for callers without a session (API): tokens are not kept
     * @return true|AuthChallenge
     *
     * @throws UserCodeInvalid|OtpAlreadyUsed|SessionExpired
     */
    public function respondToTokenChallange($type, $otp, $username, $session, bool $storeTokens = true)
    {
        $responseKey = match ($type) {
            'SOFTWARE_TOKEN_MFA' => 'SOFTWARE_TOKEN_MFA_CODE',
            'SMS_MFA' => 'SMS_MFA_CODE',
            'EMAIL_OTP' => 'EMAIL_OTP_CODE',
            'SELECT_MFA_TYPE' => 'ANSWER',
            default => throw new \InvalidArgumentException("Unsupported challenge type {$type}"),
        };
        $payload = [
            'ChallengeName' => $type,
            'ClientId' => $this->clientId,
            'Session' => $session,
            'ChallengeResponses' => [
                'USERNAME' => $username,
                $responseKey => $otp,
                'SECRET_HASH' => $this->getSecretHash($username),
            ],
        ];

        try {
            $response = $this->client->RespondToAuthChallenge($payload);
            if (isset($response['AuthenticationResult'])) {
                $this->authenticationResult = $response['AuthenticationResult'];
                if ($storeTokens) {
                    $this->storeAccessToken();
                }

                return true;
            }
            if (isset($response['ChallengeName'])) {
                return AuthChallenge::fromResult($response, $username);
            }

            throw new NotAuthorizedException('Challenge answered without tokens or a next challenge');
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                case 'NotAuthorizedException':
                    if (str_contains((string) $e->getAwsErrorMessage(), 'Invalid session')) {
                        throw new SessionExpired($e->getAwsErrorMessage());
                    }
                    throw $e;
                    break;
                case 'CodeMismatchException':
                    throw new UserCodeInvalid($e->getAwsErrorMessage());
                    break;
                case 'ExpiredCodeException':
                    if($e->getAwsErrorMessage() == 'Your software token has already been used once.'){
                        throw new OtpAlreadyUsed($e->getAwsErrorMessage());
                    }
                    throw $e;
                    break;
                default:
                    throw $e;
            }
            throw $e;
        }
    }

    /**
     * Admin call: turns every MFA factor off for the user (lost device, recovery code used).
     */
    public function disableMfa($username)
    {
        $payload = [
            'SMSMfaSettings' => [
                'Enabled' => false,
                'PreferredMfa' => false,
            ],
            'SoftwareTokenMfaSettings' => [
                'Enabled' => false,
                'PreferredMfa' => false,
            ],
            'Username' => $username,
            'UserPoolId' => $this->poolId,
        ];
        // Email MFA only exists on the Essentials/Plus tiers; LITE pools reject the key.
        if (config('cognito.email_mfa', false) === true) {
            $payload['EmailMfaSettings'] = [
                'Enabled' => false,
                'PreferredMfa' => false,
            ];
        }
        $this->client->adminSetUserMFAPreference($payload);
    }

    /**
     * Admin call: which MFA factors the user has enabled, without needing their access token.
     *
     * @return array{enabled: list<string>, preferred: ?string}
     */
    public function getMfaState($username): array
    {
        $user = $this->getUser($username);

        return [
            'enabled' => array_values($user['UserMFASettingList'] ?? []),
            'preferred' => $user['PreferredMfaSetting'] ?? null,
        ];
    }

    public function associateSoftwareToken()
    {
        try{
            $payload = [
                'AccessToken' => $this->getAccessToken(),
            ];
    
            return $this->client->AssociateSoftwareToken($payload);
        } catch (CognitoIdentityProviderException $e){            
            switch ($e->getAwsErrorCode()) {
                case 'NotAuthorizedException':
                    if ($e->getAwsErrorMessage() == 'Access Token has expired') {
                        throw new AccessTokenExpired();
                    }                    
                    throw new NotAuthorizedException();
                    break;
                case 'NEW_PASSWORD_REQUIRED':
                    throw $e;
                    break;
                default:
                    throw $e;
            }
        }
    }

    public function verifySoftwareToken($otp)
    {
        try {
            $payload = [
                'AccessToken' => $this->getAccessToken(),
                'UserCode' => $otp,
            ];
            $verify = $this->client->VerifySoftwareToken($payload);
    
            return $verify;
        } catch (CognitoIdentityProviderException $e){       
            switch ($e->getAwsErrorCode()) {
                case 'EnableSoftwareTokenMFAException':
                    if ($e->getAwsErrorMessage() == 'Code mismatch') {
                        throw new UserCodeInvalid();
                    }elseif ($e->getAwsErrorMessage() == 'Your software token has already been used once.') {
                        throw new OtpAlreadyUsed($e->getAwsErrorMessage());
                    }
                    throw $e;
                    break;
                default:
                    throw $e;
            } 
        } catch (\InvalidArgumentException $e) {
            throw new InvalidPassword($e->getMessage());
        }
    }
    public function setMFAPreferences($preferedMfa, $emailEnabled = false, $smsEnabled = false, $totpEnabled = false)
    {
        $payload = [
            'SMSMfaSettings' => [
                'Enabled' => $smsEnabled,
                'PreferredMfa' => ($preferedMfa == 'SMS_MFA' ? true : false),
            ],
            'SoftwareTokenMfaSettings' => [
                'Enabled' => $totpEnabled,
                'PreferredMfa' => ($preferedMfa == 'SOFTWARE_TOKEN_MFA' ? true : false),
            ],
            'AccessToken' => $this->getAccessToken(),
        ];
        // Email MFA only exists on the Essentials/Plus tiers; LITE pools reject the key.
        if ($emailEnabled || config('cognito.email_mfa', false) === true) {
            $payload['EmailMfaSettings'] = [
                'Enabled' => $emailEnabled,
                'PreferredMfa' => ($preferedMfa == 'EMAIL_OTP' ? true : false),
            ];
        }
        $this->client->SetUserMFAPreference($payload);
    }
    public function setMFAPreference($payload)
    {
        $payload['AccessToken'] = $this->getAccessToken();
        $this->client->SetUserMFAPreference($payload);
    }
    public function disableSoftwareTokenMfa()
    {
        $payload = [
            'SoftwareTokenMfaSettings' => [
                'Enabled' => false,
                'PreferredMfa' => false,
            ],
            'AccessToken' => $this->getAccessToken(),
        ];
        $this->client->SetUserMFAPreference($payload);
    }
    public function getMfaSettings()
    {
        try{
            $payload = [
                'AccessToken' => $this->getAccessToken(),
            ];
            $response = $this->client->GetUserAuthFactors($payload);
            return $response->toArray();
        }catch(CognitoIdentityProviderException $e){
            if ($e->getAwsErrorMessage() == 'Access Token has expired') {
                throw new AccessTokenExpired;
            }
            throw $e;
        }
    }
}
