<?php

namespace oleanti\LaravelCognito\Fortify;

use Illuminate\Support\Facades\Auth;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use oleanti\LaravelCognito\Exceptions\NotAuthorizedException;

class FortifyAuthenticate extends RedirectIfTwoFactorAuthenticatable
{
    public function handle($request, $next)
    {
        $credentials = $request->only('email', 'password');
        $remember = $request->boolean('remember');
        try {
            if (Auth::attempt($credentials, $remember)) {
                return $next($request);
            }
        } catch (NotAuthorizedException $e) {
            $this->fireFailedEvent($request);
            $this->throwFailedAuthenticationException($request);
        }
    }
}
