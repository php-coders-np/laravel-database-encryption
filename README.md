# Laravel Database Encryption Package

# This package was cloned from [here](https://github.com/elgiborsolution/laravel-database-encryption) due to the original owner's inactivity.

## Package for encrypting and decrypting model attributes for Laravel using openssl

## Key Features

- Encrypt, Decrypt database fields easily
- Minimal configuration
- Include searching encrypted data using the following:
  `whereEncrypted`, `orWhereEncrypted`
- uses openssl for encrypting and decrypting fields

## Requirements

- Laravel: >= 5
- PHP: >= 7.3

## Schema Requirements

Encrypted values are usually longer than plain text values, sometimes much longer.
You may find that the column widths in your database tables need to be altered to
store the encrypted values generated by this package.

We highly recommend to alter your column types to `TEXT` or `LONGTEXT`

## Installation

### Step 1: Composer

Via Composer command line:

```bash
$ composer require phpcodersnp/laravel-database-encryption
```
php artisan vendor:publish --provider="PHPCodersNp\DBEncryption\Providers\DBEncryptionServiceProvider"

### Step 2: Add ServiceProvider to your app/config.php file (Laravel 5.4 or below)

Add the service provider to the providers array in the config/app.php config file as follows:

```php
'providers' => [
    ...
    \PHPCodersNp\DBEncryption\Providers\DBEncryptionServiceProvider::class,
],
```

### Step 3: Publish the config file using the following Artisan command:
```bash
php artisan vendor:publish --provider="PHPCodersNp\DBEncryption\Providers\DBEncryptionServiceProvider"
```

## Usage

Use the `EncryptedAttribute` trait in any Eloquent model that you wish to apply encryption
to and define a `protected $encrypted` array containing a list of the attributes to encrypt.

For example:

```php

use PHPCodersNp\DBEncryption\Traits\EncryptedAttribute;

class User extends Eloquent {
    use EncryptedAttribute;

    /**
        * The attributes that should be encrypted on save.
        *
        * @var array
        */
    protected $encryptable = [
        'first_name', 'last_name', 'email'
    ];
}
```

By including the `EncryptedAttribute` trait, the `setAttribute()`, `getAttribute()` and `getAttributeFromArray()`
methods provided by Eloquent are overridden to include an additional step.

### Searching Encrypted Fields Example:

Searching encrypted field can be done by calling the `whereEncrypted` and `orWhereEncrypted` functions
similar to laravel eloquent `where` and `orWhere`.

```php
namespace App\Http\Controllers;

use App\User;
class UsersController extends Controller {
    public function index(Request $request)
    {
        $user = User::whereEncrypted('first_name','john')
                    ->orWhereEncrypted('last_name','!=','Doe')
                    ->orderByEncrypted('last_name','asc')
                    ->first();

        return $user;
    }
}
```

### Encrypt your current data

If you have current data in your database you can encrypt it with this command:
```bash
php artisan encryptable:encryptModel 'App\User'
```

Additionally you can decrypt it using this command:
```bash
php artisan encryptable:decryptModel 'App\User'
```

Note: You must implement first the `Encryptable` trait and set `$encryptable` attributes

### Exists and Unique Validation Rules

If you are using exists and unique rules with encrypted values replace it with exists_encrypted and unique_encrypted
```php     
$validator = validator(['email'=>'foo@bar.com'], ['email'=>'exists_encrypted:users,email']);
$validator = validator(['email'=>'foo@bar.com'], ['email'=>'unique_encrypted:users,email']);
```

## Frequently Asked Question

#### Can I search encrypted data?

YES! You will able to search on attributes which are encrypted by this package because.
If you need to search on data then use the `whereEncrypted` and `orWhereEncrypted` function:

```php
User::whereEncrypted('email','test@gmail.com')->orWhereEncrypted('email','test2@gmail.com')->firstOrFail();
```

It will automatically added on the eloquent once the model uses `EncryptedAttribute`

#### Can I encrypt all my `User` model data?

Aside from IDs you can encrypt everything you wan't

For example:
Logging-in on encrypted email

```php
$user = User::whereEncrypted('email','test@gmail.com')->filter(function ($item) use ($request) {
        return Hash::check($password, $item->password);
    })->where('active',1)->first();
```

## Credits

This package was inspired from the following:
[austinheap/laravel-database-encryption](https://github.com/austinheap/laravel-database-encryption)
[magros/laravel-model-encryption](https://github.com/magros/laravel-model-encryption)
[DustApplication/laravel-database-model-encryption](https://github.com/DustApplication/laravel-database-model-encryption.git)
[elgiborsolution/laravel-database-encryption](https://github.com/elgiborsolution/laravel-database-encryption)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
