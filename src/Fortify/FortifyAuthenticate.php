<?php

namespace OleAnti\LaravelCognito\Fortify;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Illuminate\Support\Facades\Auth;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use OleAnti\LaravelCognito\Exceptions\NotAuthorizedException;


class FortifyAuthenticate extends RedirectIfTwoFactorAuthenticatable
{
    public function handle($request, $next)
    {
        $credentials = $request->only('email', 'password');
        $remember = $request->boolean('remember');
        try {
            if(Auth::attempt($credentials, $remember)) {
                return $next($request);
            }
        } catch(NotAuthorizedException $e) {
            $this->fireFailedEvent($request);
            $this->throwFailedAuthenticationException($request);
        }
    }
}
