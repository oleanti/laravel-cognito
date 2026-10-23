Fortify
FortifyServiceProvider.php

boot:

Fortify::authenticateThrough(static function (Request $request) {
    return array_filter([
        FortifyAuthenticate::class
    ]);
});



php artisan vendor:publish --provider="oleanti\LaravelCognito\Providers\ServiceProvider" --tag="views"



User model 
    protected $fillable = [
        'cognito_username',
        'cognito_verified_at'
    ];

## Upgrading to 0.2

- `CognitoClient::authenticate()` returns `true` (tokens stored), `false`, or an
  `oleanti\LaravelCognito\AuthChallenge` when Cognito wants a second step (MFA). It no longer
  stores the challenge in the session or redirects to `cognito.routes.mfa_challenge`, and that
  config key is gone. Keep the challenge yourself and answer it with
  `respondToTokenChallange($challenge->name, $code, $challenge->username, $challenge->session)`,
  which returns `true` or the next `AuthChallenge` (`SELECT_MFA_TYPE`). Pass `storeTokens: false`
  when there is no session (APIs).
- `CognitoGuard::attempt()` and the `AuthenticatesUsers` trait return/handle the `AuthChallenge`;
  override `sendChallengeResponse()` to show a code form (the default fails the login).
- Expired access tokens are refreshed automatically. Stored results get an absolute `ExpiresAt`;
  sessions stored by 0.1.x count as expired and are refreshed on first use.
- `signUp()` with `autoconfirmusersignup` confirms the user once (0.1.x confirmed twice and
  returned the resulting exception instead of the user).
- New: `getMfaState($username)` (admin read of the enabled factors). `disableMfa()` and
  `setMFAPreferences()` only send e-mail MFA settings when `cognito.email_mfa` is true, because
  LITE pools reject them.
