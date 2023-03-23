<?php

namespace OleAnti\LaravelCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use OleAnti\LaravelCognito\Exceptions\AccessDeniedException;
use OleAnti\LaravelCognito\Exceptions\InvalidParameterException;
use OleAnti\LaravelCognito\Exceptions\LimitExceededException;
use OleAnti\LaravelCognito\Exceptions\NotAuthorizedException;
use OleAnti\LaravelCognito\Exceptions\UserNotFoundException;

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

        foreach($mappedField as $localField => $cognitoField) {
            if(array_key_exists($localField, $attributes)) {
                $fields[] = [
                    'Name' => $cognitoField,
                    'Value' => $attributes[$localField],
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
        }

        return $user;
    }

    public function initiateauth(string $username, string $password)
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

        $result = $this->client->initiateAuth($parameters);

        return $result;

    }

    public function authenticate($credentials)
    {
        $username = $credentials['email'];
        $password = $credentials['password'];
        try {

            $result = $this->initiateauth($username, $password);
        }catch(CognitoIdentityProviderException $e) {
            // https://docs.aws.amazon.com/aws-sdk-php/v3/api/class-Aws.CognitoIdentityProvider.Exception.CognitoIdentityProviderException.html
            switch ($e->getAwsErrorCode()) {
                case 'NotAuthorizedException':
                    throw new NotAuthorizedException($username);
                    break;
                case 'NEW_PASSWORD_REQUIRED':
                    dd($e);
                    break;
                default:
                    throw $e;
            }
        }

        if(isset($result['AuthenticationResult'])) {
            $this->authenticationResult = $result['AuthenticationResult'];
            $this->storeAccessToken();

            return true;
        }
        if(isset($result['ChallengeName'])) {
            session([
                'ChallengeResult' => $result,
            ]);
            if($result['ChallengeName'] == 'SMS_MFA') {

                return redirect('cognito.challange.sms');
            }
        }
        dd($result);

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
        }catch(CognitoIdentityProviderException $e) {
            if($e->getAwsErrorCode() == 'NotAuthorizedException') {
                throw ValidationException::withMessages([
                    'current_password' => __('validation.current_password'),
                ]);
            }elseif($e->getAwsErrorCode() == 'LimitExceededException') {
                throw new LimitExceededException;
            }else {
                dd($e->getAwsErrorCode());
            }
        }

        return $result;
    }

    public function createUser($username, $password, $attributes)
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
        if(count($userAttributes) > 0) {
            $parameters['UserAttributes'] = $userAttributes;
        }
        try {
            $result = $this->client->signUp($parameters);
        }catch(CognitoIdentityProviderException $e) {
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
        if((isset($result['data']['UserConfirmed']) && $result['data']['UserConfirmed']) || config('cognito.autoconfirmusersignup') === true) {
            $cognito_verified_at = now();
        }elseif($result['UserConfirmed'] === false) {
            $this->codeDeliveryDetails = $result['CodeDeliveryDetails'];
            $this->storeCodeDeliveryDetails();
        }
        $user = Cognito::userModel()::create([
            'name' => $attributes['name'],
            'email' => $username,
            'cognito_username' => $username,
            'cognito_verified_at' => $cognito_verified_at,
        ]);
        if(config('cognito.autoconfirmusersignup') === true) {
            try {
                $this->client->adminConfirmSignUp([
                    'UserPoolId' => $this->poolId,
                    'Username' => $username,
                ]);
            }catch(CognitoIdentityProviderException $e) {
                switch ($e->getAwsErrorCode()) {
                    case 'AccessDeniedException':
                        throw new NotAuthorizedException($e->getAwsErrorMessage());
                        break;
                    default:
                        return $e;

                }
            }
        }

        if(config('cognito.force_new_user_email_verified') === true) {
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
        }catch(CognitoIdentityProviderException $e) {
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
        }catch(CognitoIdentityProviderException $e) {
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
        }catch(CognitoIdentityProviderException $e) {
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
        }catch(CognitoIdentityProviderException $e) {
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

    public function storeAccessToken()
    {
       session()->put('cognito.AuthenticationResult', $this->authenticationResult);
    }

    public function storeCodeDeliveryDetails()
    {
        session()->put('cognito.CodeDeliveryDetails', $this->codeDeliveryDetails);
    }

    public function getAccessToken()
    {
        $accessResult = session('cognito.AuthenticationResult');
        $accessToken = $accessResult['AccessToken'];

        return $accessToken;
    }

    public function getCodeDeliveryDetails()
    {
        return session('cognito.CodeDeliveryDetails');
    }
}
