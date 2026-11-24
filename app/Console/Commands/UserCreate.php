<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

class UserCreate extends Command
{
    protected $signature = 'bawls:user
                            {email : Console login address}
                            {--name= : Display name (defaults to the address local part)}
                            {--password= : Skip the interactive prompt (avoid: it lands in shell history)}
                            {--keep : Leave an existing user untouched instead of resetting its password}';

    protected $description = 'Create or update a console user';

    /**
     * Scripts pass the password in this environment variable rather than as
     * an argument, where any local user could read it from the process list.
     */
    public const PASSWORD_ENV = 'BAWLS_USER_PASSWORD';

    public function handle(): int
    {
        $email = $this->argument('email');
        $name = $this->option('name') ?: str($email)->before('@')->toString();

        if ($this->option('keep') && User::where('email', $email)->exists()) {
            $this->info("Console user [{$email}] already exists; left unchanged.");

            return self::SUCCESS;
        }

        $password = $this->option('password') ?: (getenv(self::PASSWORD_ENV) ?: $this->secret('Password'));

        if (! $password) {
            $this->error('A password is required.');

            return self::FAILURE;
        }

        $validator = Validator::make(
            ['email' => $email, 'password' => $password],
            [
                'email' => ['required', 'email'],
                'password' => ['required', Password::min(12)->letters()->numbers()],
            ],
        );

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $error) {
                $this->error($error);
            }

            return self::FAILURE;
        }

        $user = User::updateOrCreate(
            ['email' => $email],
            ['name' => $name, 'password' => $password],   // hashed by the model's cast
        );

        $this->info($user->wasRecentlyCreated
            ? "Created console user [{$email}]."
            : "Updated password for [{$email}].");

        return self::SUCCESS;
    }
}
