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

/**
 * Class SaltRegex
 *
 * Class that contains the different salt regex patterns supported by this package.
 *
 * @package     axelitus\Security
 * @see         http://www.php.net/manual/es/function.crypt.php     PHP crypt function reference
 */
abstract class SaltRegex
{
    /**
     * @var string  Standard DES salt regex pattern.
     */
    const STD_DES = '/^(?:[0-9A-Za-z]|\.|\/){2}$/';

    /**
     * @var string  Extended DES salt regex pattern.
     */
    const EXT_DES = '/^_(?:[0-9A-Za-z]|\.|\/){8}$/';

    /**
     * @var string  MD5 salt regex pattern.
     */
    const MD5 = '/^\$1\$(?:[0-9A-Za-z]|\.|\/|_|\+|-){8}\$$/';

    /**
     * @var string  Blowfish salt regex pattern.
     */
    const BLOWFISH = '/^\$2a\$(0[4-9]|[12][0-9]|3[01])\$(?:[0-9A-Za-z]|\.|\/){22}\$?$/';

    /**
     * @var string  SHA256 salt regex pattern.
     */
    const SHA256 = '/^\$5\$(?:rounds=\d+\$)?(?:[0-9A-Za-z]|\.|\/){16}\$$/';

    /**
     * @var string  SHA512 salt regex pattern.
     */
    const SHA512 = '/^\$6\$(?:rounds=\d+\$)?(?:[0-9A-Za-z]|\.|\/){16}\$$/';

    /**
     * Tries to match the salt against the Standard DES regex pattern.
     *
     * Tries to match the salt against the Standard DES regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchStdDes($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::STD_DES) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the Extended DES regex pattern.
     *
     * Tries to match the salt against the Extended DES regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchExtDes($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::EXT_DES) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the MD5 regex pattern.
     *
     * Tries to match the salt against the MD5 regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchMd5($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::MD5) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the Blowfish regex pattern.
     *
     * Tries to match the salt against the Blowfish regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchBlowfish($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::BLOWFISH) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the SHA256 regex pattern.
     *
     * Tries to match the salt against the SHA256 regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchSha256($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::SHA256) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the SHA512 regex pattern.
     *
     * Tries to match the salt against the SHA512 regex pattern. The match is done using
     * axelitus\Base\String::match() and the class defined proper regex pattern.
     *
     * @param   string $salt The salt to be matched against the pattern.
     *
     * @return  bool    Whether the salt matched against the regex pattern.
     * @throws \InvalidArgumentException
     */
    public static function matchSha512($salt)
    {
        if (!is_string($salt) and $salt != '') {
            throw new \InvalidArgumentException("The \$salt parameter must be a non-empty string.");
        }

        if (String::match($salt, static::SHA512) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Tries to match the salt against the given salt type.
     *
     * @param string $salt     The salt to be matched against the pattern.
     * @param string $saltType The type of the salt to match against.
     *
     * @return  bool    Whether the salt matched against the given salt type.
     * @throws \InvalidArgumentException
     */
    public static function match($salt, $saltType)
    {
        switch ($saltType) {
            case SaltType::GENERIC:
                // Generic is a loose salt type, so whatever is given is matched.
                $ret = true;
                break;
            case SaltType::STD_DES:
                $ret = static::matchStdDes($salt);
                break;
            case SaltType::EXT_DES:
                $ret = static::matchExtDes($salt);
                break;
            case SaltType::MD5:
                $ret = static::matchMd5($salt);
                break;
            case SaltType::BLOWFISH:
                $ret = static::matchBlowfish($salt);
                break;
            case SaltType::SHA256:
                $ret = static::matchSha256($salt);
                break;
            case SaltType::SHA512:
                $ret = static::matchSha512($salt);
                break;
            default:
                throw new \InvalidArgumentException("The \$saltType parameter must be a valid salt type.");
                break;
        }

        return $ret;
    }
}
