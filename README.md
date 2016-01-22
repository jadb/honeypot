# Honeypot

The [Project Honey Pot](https://www.projecthoneypot.org)'s *un-official* PHP SDK.

Using the library, you can start auto-detecting bad visitors (`HttpBL`) and/or help 
deterring new ones (`Quicklink`).

## Install

```
composer require jadb/honeypot:1.0.x-dev
```

## Usage

### HttpBL

To use the [Http::BL](https://www.projecthoneypot.org/httpbl_api.php) API, you will first need 
an API key. Head over and [register](http://www.projecthoneypot.org?rf=202881) if you haven't
already (this is a referral link): 

Once you have that, you can just do:

```php
<?php

if (!(new \Honeypot\HttpBL('your-api-key'))->isSafe('127.0.0.1') {
    exit('Unsafe visitor');
}
```

If you want more control over the rules:

```php
<?php
/**
 * By default, strict mode is used. When not in strict mode, any pass is a pass. This ruleset
 * translates to: 5 days or older, or threat score lower than 2, or visitor type lower than 4.
 */
$strict = false; 
$age = 5; 
$score = 2;
$type = 4;
if (!(new \Honeypot\HttpBL('your-api-key'))->isSafe('127.0.0.1', $age, $score, $type) {
    exit('Unsafe visitor');
}
```

For even more, you could just get the `Address` object and create your own validation:

```php
<?php
$address = (new \Honeypot\HttpBL('your-api-key'))->address('127.0.0.1');
```

**NOTE:** For testing purposes, [dummy data is made available](https://www.projecthoneypot.org/httpbl_api.php).

### Quicklink

To use [quicklinks](https://www.projecthoneypot.org/manage_quicklink.php) and help deterring new bad IPs, 
you will need to get a honeypot's URL or [host your own honeypot](https://www.projecthoneypot.org/manage_honey_pots.php).

Once that is done, you can create up to 8 different links by doing:

```php
<?php
// this will create 5 links
echo (new \Honeypot\Quicklink('http://link.to.honeypot.org/'))->render(5);
```

## Patches & Features

* Fork
* Mod, fix
* Test - this is important, so it's not unintentionally broken
* Commit - do not mess with license, todo, version, etc. (if you do change any, bump them into commits of
their own that I can ignore when I pull)
* Pull request - bonus point for topic branches

To ensure your PRs are considered for upstream, you MUST follow the PSR2 coding standards.

## Bugs & Feedback

http://github.com/jadb/honeypot/issues

## License

Copyright (c) 2015, [Jad Bitar](http://jadb.io) and licensed under [The MIT License](http://www.opensource.org/licenses/mit-license.php).
