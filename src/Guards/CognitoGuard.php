<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OleAnti\LaravelCognito\Guards;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Traits\Macroable;
use OleAnti\LaravelCognito\CognitoClient;
use Symfony\Component\HttpFoundation\Request;

//class CognitoGuard implements Guard
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
        $result = $this->client->authenticate($credentials);

        if ($result && $user instanceof Authenticatable) {
            return true;
        }

        return false;
    }
}
