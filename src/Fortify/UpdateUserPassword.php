<?php

namespace OleAnti\LaravelCognito\Fortify;

use App\Actions\Fortify\PasswordValidationRules;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\UpdatesUserPasswords;
use OleAnti\LaravelCognito\CognitoClient;

class UpdateUserPassword implements UpdatesUserPasswords
{
    use PasswordValidationRules;

    /**
     * Validate and update the user's password.
     *
     * @param  array<string, string>  $input
     */
    public function update(User $user, array $input): void
    {
        $validator = Validator::make($input, [
            'current_password' => ['required', 'string'],
            'password' => $this->passwordRules(),
        ], [
            'current_password.current_password' => __('The provided password does not match your current password.'),
        ]);
        $validator->validateWithBag('updatePassword');

        $cognitoClient = app(CognitoClient::class);
        $cognitoClient->changePassword($cognitoClient->getAccessToken(), $input['current_password'], $input['password']);

    }
}
