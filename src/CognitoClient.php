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
use oleanti\LaravelCognito\Exceptions\NotAuthorizedException;
use oleanti\LaravelCognito\Exceptions\SessionExpired;
use oleanti\LaravelCognito\Exceptions\UserCodeInvalid;
use oleanti\LaravelCognito\Exceptions\UserNotConfirmedException;
use oleanti\LaravelCognito\Exceptions\UserNotFoundException;
use oleanti\LaravelCognito\Exceptions\OtpAlreadyUsed;

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
        } catch (CognitoIdentityProviderException $e) {
            return false;
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

    public function authenticate($credentials)
    {
        $username = $credentials['email'];
        $password = $credentials['password'];
        try {
            $result = $this->initiateauth($username, $password);
        } catch (CognitoIdentityProviderException $e) {
            // https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CognitoIdentityProvider.Exception.CognitoIdentityProviderException.html
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
            $class = config('cognito.accesstokenstorage');
            $storage = new $class;
            $storage->set($result->toArray());

            return redirect(route(config('cognito.routes.mfa_challenge')));
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
                dd($e->getAwsErrorCode());
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
            $this->client->adminSetUserPassword($parameters);
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
                        Cognito::username() => [$e->getAwsErrorMessage()],
                    ]);
                    break;
                case 'UsernameExistsException':
                    throw ValidationException::withMessages([
                        Cognito::username() => trans('validation.unique', [
                            'attribute' => Cognito::username(),
                        ]),
                    ]);
                    break;
                default:
                    throw $e;
            }

        }
        $cognito_verified_at = null;
        if ((isset($result['data']['UserConfirmed']) && $result['data']['UserConfirmed']) || config('cognito.autoconfirmusersignup') === true) {
            $cognito_verified_at = now();
        } elseif ($result['UserConfirmed'] === false) {
            $this->codeDeliveryDetails = $result['CodeDeliveryDetails'];
            $this->storeCodeDeliveryDetails();
        }
        $user = Cognito::userModel()::create([
            'name' => $attributes['name'],
            'email' => $username,
            'cognito_username' => $username,
            'cognito_verified_at' => $cognito_verified_at,
        ]);
        if (config('cognito.autoconfirmusersignup') === true) {
            try {
                $this->client->adminConfirmSignUp([
                    'UserPoolId' => $this->poolId,
                    'Username' => $username,
                ]);
            } catch (CognitoIdentityProviderException $e) {
                switch ($e->getAwsErrorCode()) {
                    case 'AccessDeniedException':
                        throw new NotAuthorizedException($e->getAwsErrorMessage());
                        break;
                    default:
                        return $e;

                }
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
        $username = auth()->user()->{config('cognito.username')};

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

    public function getAccessToken()
    {
        $class = config('cognito.accesstokenstorage');
        $storage = new $class;
        $authResult = $storage->get();
        $token = $authResult->getAwsToken();

        if ($token->isExpired() && false) {
            $this->refreshAccessToken();
            $result = $storage->get();
            $token = $result->getAwsToken();
        }

        return $token->getToken();
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

    public function respondToTokenChallange($otp, $username, $session)
    {
        $payload = [
            'ChallengeName' => 'SOFTWARE_TOKEN_MFA',
            'ClientId' => $this->clientId,
            'Session' => $session,
            'ChallengeResponses' => [
                'USERNAME' => $username,
                'SOFTWARE_TOKEN_MFA_CODE' => $otp,
                'SECRET_HASH' => $this->getSecretHash($username),
            ],
        ];
        try {
            $response = $this->client->RespondToAuthChallenge($payload);

            return $response;
        } catch (CognitoIdentityProviderException $e) {
            switch ($e->getAwsErrorCode()) {
                case 'NotAuthorizedException':
                    if ($e->getAwsErrorMessage() == 'Invalid session for the user, session is expired.') {
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
        $this->client->adminSetUserMFAPreference($payload);
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
            $payload = [
                'SMSMfaSettings' => [
                    'Enabled' => false,
                    'PreferredMfa' => false,
                ],
                'SoftwareTokenMfaSettings' => [
                    'Enabled' => true,
                    'PreferredMfa' => true,
                ],
                'AccessToken' => $this->getAccessToken(),
            ];
            $this->client->SetUserMFAPreference($payload);
    
            return $verify;
        } catch (CognitoIdentityProviderException $e){       
            switch ($e->getAwsErrorCode()) {
                case 'EnableSoftwareTokenMFAException':
                    if ($e->getAwsErrorMessage() == 'Code mismatch') {
                        throw new UserCodeInvalid();
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
}
