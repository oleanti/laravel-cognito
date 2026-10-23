<?php

namespace oleanti\LaravelCognito;

/**
 * A Cognito challenge (MFA, NEW_PASSWORD_REQUIRED, ...) returned instead of tokens.
 * The caller keeps it (session, cache) and answers it with respondToTokenChallange().
 */
class AuthChallenge
{
    /**
     * @param  string  $name  ChallengeName, e.g. SOFTWARE_TOKEN_MFA
     * @param  string  $session  Cognito challenge session (valid for the client's auth_session_validity)
     * @param  string  $username  Cognito username (USER_ID_FOR_SRP), used for USERNAME and SECRET_HASH
     * @param  array<string, string>  $parameters  ChallengeParameters
     */
    public function __construct(
        public readonly string $name,
        public readonly string $session,
        public readonly string $username,
        public readonly array $parameters = [],
    ) {}

    public static function fromResult($result, string $fallbackUsername): self
    {
        $parameters = $result['ChallengeParameters'] ?? [];

        return new self(
            $result['ChallengeName'],
            $result['Session'] ?? '',
            $parameters['USER_ID_FOR_SRP'] ?? $fallbackUsername,
            $parameters,
        );
    }

    /**
     * @return array{name: string, session: string, username: string, parameters: array<string, string>}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'session' => $this->session,
            'username' => $this->username,
            'parameters' => $this->parameters,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self($data['name'], $data['session'], $data['username'], $data['parameters'] ?? []);
    }
}
