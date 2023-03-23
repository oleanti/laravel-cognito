<?php

namespace oleanti\LaravelCognito\Providers;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Illuminate\Routing\Router;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use oleanti\LaravelCognito\Cognito;
use oleanti\LaravelCognito\CognitoClient;
use oleanti\LaravelCognito\Console\UserTableCommand;
use oleanti\LaravelCognito\Guards\CognitoGuard;
use oleanti\LaravelCognito\Http\Middleware\UserMustBeConfirmed;
use oleanti\LaravelCognito\Observers\UserObserver;

/**
 * Class ServiceProvider.
 */
class ServiceProvider extends AuthServiceProvider
{
    public function register()
    {
      $this->app->register(EventServiceProvider::class);
    }

    public function boot(): void
    {

        $this->configureRoutes();

        $this->mergeConfigFrom(
            __DIR__.'/../../config/config.php', 'cognito'
        );
        $this->extendAuthGuard();

        if ($this->app->runningInConsole()) {
            $this->commands([
                UserTableCommand::class,
            ]);
        }

        $this->app->singleton(CognitoClient::class, function (Application $app) {
            $config = [
                'region' => config('cognito.region'),
                'version' => config('cognito.version'),
            ];

            $credentials = config('cognito.credentials');

            if (! empty($credentials['key']) && ! empty($credentials['secret'])) {
                $config['credentials'] = Arr::only($credentials, ['key', 'secret', 'token']);
            }

            return new CognitoClient(
                new CognitoIdentityProviderClient($config),
                config('cognito.app_client_id'),
                config('cognito.app_client_secret'),
                config('cognito.user_pool_id')
            );
        });

        if ($this->app->runningInConsole()) {
            // Publish views
            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views'),
            ], 'views');
        }

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('usermustbeconfirmed', UserMustBeConfirmed::class);
        $userModelClassName = Cognito::userModel();
        if (class_exists($userModelClassName)) {

            $userModel = new $userModelClassName;
            $userModel->observe(UserObserver::class);
        }
    }

    protected function extendAuthGuard()
    {
        Auth::extend('cognito', function (Application $app, string $name, array $config) {
            $guard = new CognitoGuard(
                $name,
                $client = $app->make(CognitoClient::class),
                Auth::createUserProvider($config['provider']),
                $app['session.store'],
                $app['request']
            );
            $guard->setCookieJar($this->app['cookie']);
            $guard->setDispatcher($this->app['events']);
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));

            return $guard;
        });
    }

    /**
     * Configure the routes offered by the application.
     *
     * @return void
     */
    protected function configureRoutes()
    {
        Route::group([
            'namespace' => 'oleanti\LaravelCognito\Http\Controllers',
            'domain' => config('cognito.domain', null),
            'prefix' => config('cognito.prefix', config('cognito.path')),
        ], function () {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        });
    }
}
