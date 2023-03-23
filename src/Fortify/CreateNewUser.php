<?php

namespace OleAnti\LaravelCognito\Fortify;

use App\Actions\Fortify\PasswordValidationRules;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\CreatesNewUsers;
use Laravel\Jetstream\Jetstream;
use OleAnti\LaravelCognito\CognitoClient;

class CreateNewUser implements CreatesNewUsers
{
    use PasswordValidationRules;

    /**
     * Validate and create a newly registered user.
     *
     * @param  array<string, string>  $input
     */
    public function create(array $input)
    {
        Validator::make($input, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            //'password' => $this->passwordRules(),
            'password' => ['required'],
            'terms' => Jetstream::hasTermsAndPrivacyPolicyFeature() ? ['accepted', 'required'] : '',
        ])->validate();
        $attributes = [];
        $attributes['name'] = $input['name'];
        $attributes['email'] = $input['email'];

        $cognitoClient = app(CognitoClient::class);

        return $cognitoClient->createUser($input['email'], $input['password'], $attributes);
    }
}
