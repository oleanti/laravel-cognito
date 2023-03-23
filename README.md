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
