# Package axelitus/security

A framework agnostic PHP package that contains security related classes and helpers.

## Package Information

* **Package:** axelitus/security [![Total Downloads](https://poser.pugx.org/axelitus/security/downloads.png)](https://packagist.org/packages/axelitus/security)
* **Root Namespace:** axelitus\Security
* **Author:** Axel Pardemann (axelitusdev@gmail.com)
* **Repository**: [axelitus/php-base](https://github.com/axelitus/php-security "axelitus/php-security at GitHub") at GitHub
* **Build Status (master):** [![Build Status](https://secure.travis-ci.org/axelitus/php-security.png?branch=master)](http://travis-ci.org/axelitus/php-security) [![Latest Stable Version](https://poser.pugx.org/axelitus/security/v/stable.png)](https://packagist.org/packages/axelitus/security)
* **Build Status (develop):** [![Build Status](https://secure.travis-ci.org/axelitus/php-security.png?branch=develop)](http://travis-ci.org/axelitus/php-security) [![Latest Unstable Version](https://poser.pugx.org/axelitus/security/v/unstable.png)](https://packagist.org/packages/axelitus/security)
* **Composer Package:** [axelitus/security](http://packagist.org/packages/axelitus/security "axelitus/security at Packagist") at Packagist
* **Issue Tracker:** [axelitus/php-security](https://github.com/axelitus/php-security/issues "axelitus/php-security Issue Tracker at GitHub") Issue Tracker at GitHub

## Requirements

The requirements for this package to work are the following:

* PHP >= 5.4.9 (it may work for previous 5.4.X versions but it is not tested).

## Standards

This package is intended to follow some standards for easy contributions and usage. Recently there has been an initiative to standardize the interoperation of frameworks, though I think this easily extends to most pieces of code everyone is building. The group behind all this is the [PHP-FIG (Framework Interoperability Group)](http://www.php-fig.org), you should pay them a visit at their site.

There are already some standards marked as accepted (_final_): [PSR-0](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-0.md), [PSR-1](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md), [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md) and [PSR-3](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-3-logger-interface.md).

**This package is intentend to be PSR-2 compliant.**

Being PSR-2 compliant means this package can be easily installed by using [Composer](getcomposer.org) from the [Packagist](http://packagist.org) package archive. Just follow the instructions in section [How to install](#how-to-install). It also means that there's a [guide for coding styles](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md) and the developers and contributors should enforce this for everyone's benefit.

## Contents

All classes are referenced from the package namespace if not otherwise stated.

 - **CLASS** - CLASS description.

## How to install

To install this package and use it in your app just follow these instructions (if you haven't read the documentation from [Composer](http://getcomposer.org) please do so before you continue):

1. Download composer if you haven't already done so (use your preferred method). Example:
```
    $ curl -s https://getcomposer.org/installer | php
```

2. Place a `require` statement inside your `composer.json` file replacing `<version>` with the desired version. Example:
```
    "require": {
        "axelitus/secuity": "<version>"
    }
```

3. Run the composer installer to resolve dependencies and download the packages. Example:
```
    $ php composer.phar install
```

4. In order to use the packages you have to _load_ the autoloader that was generated by composer (if you are using a framework, maybe this is already done automatically). Example:
```
    require 'vendor/autoload.php';
```

5. Finally just use the package classes as needed:
```
    axelitus\Security\[<sub-namespace>\...]<class>::<function>(<params>);
```