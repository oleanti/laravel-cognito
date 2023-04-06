<?php

namespace oleanti\LaravelCognito\Observers;

use oleanti\LaravelCognito\Cognito;
use oleanti\LaravelCognito\CognitoClient;

class UserObserver
{
    public function updated($model)
    {
        $cognitoClient = app(CognitoClient::class);
        $cognitoFieldsChanged = $cognitoClient->mapUserAttributesToCognito($model->getChanges());
        if(count($cognitoFieldsChanged) > 0) {
            $cognitoFieldsChanged = $this->runCasts($cognitoFieldsChanged, $model);
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
    private function runCasts($cognitoAttributes, $model){
        foreach($cognitoAttributes as &$attribute){
            if(array_key_exists($attribute['Name'], config('cognito.cognito_field_caster'))){
                $casterClass = config('cognito.cognito_field_caster')[$attribute['Name']];
                $caster = new $casterClass();
                $key = $this->getModelAttributeName($attribute['Name']);
                $cognitoValue = $caster->set($model, $key, $attribute['Value'], $model->getAttributes());
                $attribute['Value'] = $cognitoValue;
            }
        }
        return $cognitoAttributes;
    }
    private function getModelAttributeName(string $cognitoAttributeName){
        return array_search($cognitoAttributeName, config('cognito.usermodel_mapping'));
    }
}
