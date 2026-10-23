<?php

namespace oleanti\LaravelCognito\AccessToken;

use Carbon\Carbon;
use Illuminate\Support\Facades\App;
use oleanti\LaravelCognito\Exceptions\NoAccessTokenAvailable;

class SessionStorage implements AuthenticationResultStorageInterface
{
    /**
     * Per instance, never static: under Octane a static copy would outlive the request and be
     * merged into the next user's session.
     */
    protected ?AuthResult $cache = null;

    public function __construct($initalData = null)
    {
        if (is_array($initalData)) {
            $this->cache = new AuthResult($initalData);
        }
    }

    public function get(): AuthResult
    {
        $accessResult = App::make('session')->get('cognito.AuthenticationResult');
        if (! is_array($accessResult)) {
            throw new NoAccessTokenAvailable;
        }
        $this->cache = new AuthResult($accessResult);

        return $this->cache;
    }

    public function set(array $result)
    {
        if (is_null($this->cache)) {
            try {
                $current = $this->get()->getAccessResultArray();
            } catch (NoAccessTokenAvailable $e) {
                $current = [];
            }
        } else {
            $current = $this->cache->getAccessResultArray();
        }

        // Cognito returns a relative lifetime; keep the absolute expiry next to it.
        if (isset($result['ExpiresIn'])) {
            $result['ExpiresAt'] = Carbon::now()->getTimestamp() + (int) $result['ExpiresIn'];
        }

        App::make('session')->put('cognito.AuthenticationResult', array_merge($current, $result));
    }

    public function getAll()
    {
        return App::make('session')->get('cognito.AuthenticationResult');
    }

    public function getCached()
    {
        return $this->cache;
    }
}
