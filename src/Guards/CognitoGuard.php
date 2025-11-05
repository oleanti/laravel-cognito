<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace oleanti\LaravelCognito\Guards;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Traits\Macroable;
use oleanti\LaravelCognito\Actions\GetUser;
use oleanti\LaravelCognito\CognitoClient;
use oleanti\LaravelCognito\Exceptions\NoLocalUserException;
use oleanti\LaravelCognito\Exceptions\NotAuthorizedException;
use oleanti\LaravelCognito\Exceptions\InvalidPassword;
use Symfony\Component\HttpFoundation\Request;

class CognitoGuard extends SessionGuard implements StatefulGuard
{
    use GuardHelpers, Macroable;

    /**
     * @var CognitoClient
     */
    protected $client;

    /**
     * CognitoGuard constructor.
     */
    public function __construct(
        string $name,
        CognitoClient $client,
        UserProvider $provider,
        Session $session,
        ?Request $request = null
    ) {
        $this->client = $client;
        parent::__construct($name, $provider, $session, $request);
    }

    /**
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     *
     * @throws InvalidUserModelException
     */
    protected function hasValidCredentials($user, $credentials)
    {
        try {
            $result = $this->client->authenticate($credentials);
        } catch (InvalidPassword $e) {
            return false;        
        } catch (NotAuthorizedException $e) {
            return false;
        }
        if ($result instanceof RedirectResponse) {
            return $result;
        }
        if ($result && $user instanceof Authenticatable) {
            return true;
        }
        if (! $user instanceof Authenticatable) {
            throw new NoLocalUserException;
        }

        return false;
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  bool  $remember
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);

        //$this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        $this->lastAttempted = $user = GetUser::retrieveByCredentials($credentials, $this->provider);

        $attempt = $this->hasValidCredentials($user, $credentials);
        if ($attempt === true) {
            $this->login($user, $remember);

            return true;
        } elseif ($attempt === false) {
            $this->fireFailedEvent($user, $credentials);

            return false;
        }

        return $attempt;

    }
}
