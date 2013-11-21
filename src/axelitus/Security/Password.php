<?php
/**
 * Part of composer package: axelitus/security
 *
 * @package     axelitus\Security
 * @version     0.1
 * @author      Axel Pardemann (axelitusdev@gmail.com)
 * @license     MIT License
 * @copyright   2013 - Axel Pardemann
 * @link        http://axelitus.mx/projects/axelitus/security
 */

namespace axelitus\Security;

use axelitus\Base\String;

class Password
{
    /**
     * Creates a secure password hash using the concatenation of a salt.
     *
     * @param        $password
     * @param null   $salt
     * @param string $algorithm
     * @param bool   $removeSalt
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public static function secure($password, $salt = null, $algorithm = HashAlgorithm::SHA1, $removeSalt = false)
    {
        if (!String::is($password)) {
            throw new \InvalidArgumentException("The \$password must be a string.");
        }

        $salt = (is_null($salt) or !String::is($salt)) ? Salt::generic() : $salt;
        $hash = Hash::calculate($salt . $password, $algorithm);

        return ($removeSalt) ? $hash : $salt . '$' . $hash;
    }

    /**
     * Creates a secure password using the crypt function.
     *
     * @param $password
     * @param $salt
     *
     * @return string
     * @throws \InvalidArgumentException
     * @see         http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
     */
    public static function crypt($password, $salt)
    {
        if (!String::is($password) or !String::is($salt)) {
            throw new \InvalidArgumentException("The \$password and \$salt must be strings.");
        }

        return crypt($password, $salt);
    }

    public static function validateSecureSalted($password, $saltedHash, $algorithm = HashAlgorithm::SHA1)
    {
        if (!String::is($password) or !String::is($saltedHash)) {
            throw new \InvalidArgumentException("The \$password and the \$saltedHash must be strings.");
        }

        if (($pos = String::pos($saltedHash, '$')) === false) {
            throw new \InvalidArgumentException("The \$saltedHash parameter is incorrect.");
        }

        $salt = String::sub($saltedHash, 0, $pos);
        $hash = static::secure($password, $salt, $algorithm);

        return ($hash == $saltedHash);
    }

    public static function validateSecure($password, $salt, $hash, $algorithm = HashAlgorithm::SHA1)
    {
        return static::validateSecureSalted($password, $salt.'$'.$hash, $algorithm);
    }

    public static function validateCrypt($password, $saltedHash)
    {
        if (!String::is($password) or !String::is($saltedHash)) {
            throw new \InvalidArgumentException("The \$password and the \$saltedHash must be strings.");
        }

        $hash = static::crypt($password, $saltedHash);

        return ($saltedHash== $hash);
    }
}
