<?php

namespace OleAnti\LaravelCognito\Observers;

use OleAnti\LaravelCognito\Cognito;
use OleAnti\LaravelCognito\CognitoClient;

class UserObserver
{
    public function updated($model)
    {
        $cognitoClient = app(CognitoClient::class);
        $cognitoFieldsChanged = $cognitoClient->mapUserAttributesToCognito($model->getChanges());
        if(count($cognitoFieldsChanged) > 0) {
            $cognitoClient->adminUpdateUserAttributes($model->{Cognito::username()}, $cognitoFieldsChanged);
        }
    }

    public function deleted($model)
    {
        if(config('cognito.delete_cognito_user_on_model_delete') === true) {
            $cognitoClient = app(CognitoClient::class);
            $cognitoClient->adminDeleteUser($model->{Cognito::username()});
        }
    }
}
