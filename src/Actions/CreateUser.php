<?php

namespace oleanti\LaravelCognito\Actions;

use Illuminate\Support\Carbon;
use oleanti\LaravelCognito\Cognito;
use oleanti\LaravelCognito\CognitoClient;

class CreateUser
{
    public static function createFromCognito($username)
    {
        $cognitoClient = app(CognitoClient::class);
        $cognitoUser = $cognitoClient->getUser($username);
        if ($cognitoUser == false) {
            return;
        }
        $attributes = $cognitoUser->toArray()['UserAttributes'];

        $modelAttributes = self::mapCognitoAttributesToUserModel($attributes);
        $userAttributes = array_merge($modelAttributes, [
            'email' => $username,
            'cognito_username' => $username,
        ]);

        return Cognito::userModel()::create($userAttributes);
    }

    public static function mapCognitoAttributesToUserModel($attributes): array
    {
        $fields = [];
        $mappedField = config('cognito.usermodel_mapping');
        foreach ($attributes as $attribute) {
            $cognitoFieldName = $attribute['Name'];
            if ($key = array_search($cognitoFieldName, $mappedField)) {
                $cognitoFieldValue = $attribute['Value'];
                $fields[$key] = $cognitoFieldValue;
            }
            if ($attribute['Name'] == 'email_verified' && $attribute['Value'] == 'true' && config('cognito.email_verified_at')) {
                $fields['email_verified_at'] = Carbon::now();
            }
            if ($attribute['Name'] == 'phone_number_verified' && config('cognito.phone_verified_at')) {
                $fields['phone_verified_at'] = Carbon::now();
            }
        }

        return $fields;
    }
}
