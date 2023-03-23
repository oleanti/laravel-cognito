<?php

namespace OleAnti\LaravelCognito\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class UserMustBeConfirmed
{
    /**
     * Handle an incoming request.
     *
     * @param  string[]  ...$guards
     * @return mixed
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if($user->cognito_verified_at === null) {
            return redirect($this->redirectTo($request));
        }

        return $next($request);
    }

    /**
     * Get the path the user should be redirected to when they are not authenticated.
     *
     * @return string|null
     */
    protected function redirectTo(Request $request)
    {
        return route('cognito.verification');
    }
}
