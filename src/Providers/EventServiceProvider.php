<?php

namespace oleanti\LaravelCognito\Providers;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
use oleanti\LaravelCognito\Listeners\SaveStuff;

class EventServiceProvider extends ServiceProvider
{
    protected $listen = [
        Authenticated::class => [
            SaveStuff::class,
        ],
    ];

    /**
     * Register any events for your application.
     *
     * @return void
     */
    public function boot()
    {
        parent::boot();
    }
}
