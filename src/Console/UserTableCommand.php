<?php

namespace OleAnti\LaravelCognito\Console;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Composer;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'cognito:table')]
class UserTableCommand extends Command
{
    /**
     * The console command name.
     *
     * @var string
     */
    protected $name = 'cognito:table';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a migration for the user database table';

    /**
     * The filesystem instance.
     *
     * @var \Illuminate\Filesystem\Filesystem
     */
    protected $files;

    /**
     * @var \Illuminate\Support\Composer
     *
     * @deprecated Will be removed in a future Laravel version.
     */
    protected $composer;

    /**
     * Create a new session table command instance.
     *
     * @return void
     */
    public function __construct(Filesystem $files, Composer $composer)
    {
        parent::__construct();

        $this->files = $files;
        $this->composer = $composer;
    }

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $fullPath = $this->createBaseMigration();

        $this->files->put($fullPath, $this->files->get(__DIR__.'/stubs/database.stub'));

        $this->components->info('Migration created successfully.');
    }

    /**
     * Create a base migration file for the session.
     *
     * @return string
     */
    protected function createBaseMigration()
    {
        $name = 'cognito_alter_user_table';

        $path = $this->laravel->databasePath().'/migrations';

        return $this->laravel['migration.creator']->create($name, $path);
    }
}
